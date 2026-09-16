<?php
/**
 * magento-key-rotation.php - one tool for the whole Magento 2 encryption-key rotation problem.
 *
 * Run from the Magento root (or pass --magento-root). It bootstraps Magento and uses Magento's OWN
 * encryptor for every decrypt and encrypt, so key formats (legacy 32-char, 2.4.7+ 'base64...'),
 * multiple whitespace-separated keys, and every cipher Magento can still read are handled exactly
 * as Magento handles them. No crypto is re-implemented here.
 *
 *   scan        Inventory every text AND binary column of every table for Magento ciphertext, whole
 *               values and values EMBEDDED inside JSON / serialized PHP / query strings. Reports
 *               counts per key:cipher version, tables without a primary key, legacy ciphers, and a
 *               diagnosis with a fix for every value that cannot be decrypted.
 *   explain     Take one ciphertext (--value=..., or --table/--column/--id) and spell out what its
 *               prefix means, which key line it needs, whether it decrypts, and if not, why not.
 *   encrypt     Produce one encrypted value, for pasting into a row by hand. Uses the latest key in
 *               env.php unless --key says otherwise, and says whether this site can read it back.
 *   code-scan   Inventory app/code and vendor for extensions that encrypt with Magento's encryptor
 *               (rotated by a key change) versus their OWN crypto (invisible to any DB scan and NOT
 *               rotated; needs that extension's own procedure).
 *   re-encrypt  Decrypt everything on an older key and re-encrypt with the LATEST key in env.php,
 *               including embedded ciphertext (JSON escaping and serialized-string lengths are
 *               preserved). Rows without a primary key are updated by exact old value, which is
 *               unique because every ciphertext carries a random nonce. Dry run by default.
 *   verify      Exit 0 only when every ciphertext in the database is on the latest key. The gate to
 *               pass before older keys are retired.
 *   retire-keys Retire every key except the latest by OVERWRITING it with a random value in env.php,
 *               keeping the number and order of lines. NEVER delete key lines: the key version stored
 *               in every ciphertext ("2:3:...") is the line position, so deleting lines shifts every
 *               index and makes all data unreadable (a rehearsal produced exactly that: an HTTP 500
 *               storefront). Refuses to run unless verify would pass. Dry run unless --apply; backs up
 *               env.php first.
 *
 * Options
 *   --magento-root=PATH     default: directory of this script
 *   --tables=a,b            only these tables            --exclude=a,b   skip these tables
 *   --max-rows=N            skip tables above N estimated rows during scan/verify (default 0 = none)
 *   --apply                 re-encrypt: actually write. Without it nothing is changed.
 *   --dump=FILE             re-encrypt: write UPDATE statements to FILE and reverse statements to FILE.backup.sql
 *   --old-key=KEY           decrypt fallback for values on a key that is no longer in env.php (sodium only)
 *   --limit=N               re-encrypt: stop after N rows (for a staged rollout)
 *   --allow-binary          re-encrypt: also re-encrypt values whose decrypted form is not printable text.
 *                           For cipher 3 this is safe (the authentication tag proves the key was right and
 *                           the plaintext really is binary); for the mcrypt ciphers 0-2 non-text output
 *                           usually means the wrong key, so those stay skipped either way.
 *   --show-all              list every problem value instead of the first few of each kind
 *   --reveal                explain: print the decrypted plaintext (it is hidden by default)
 *   --no-color              plain output (also honoured: NO_COLOR, and any non-terminal output)
 *
 * Workflow:  scan  ->  add the new key (bin/magento encryption:key:change, keeps the old key)  ->
 *            bin/magento encryption:data:re-encrypt  ->  re-encrypt --dump=... (review)  ->
 *            re-encrypt --apply  ->  verify (exit 0)  ->  retire-keys --apply  ->  cache:flush  ->
 *            test payments, integrations, mail, admin 2FA  ->  rotate secrets at source.
 */
declare(strict_types=1);

const WHOLE_RE    = '/^(\d{1,2}):([0-3]):([A-Za-z0-9+\/]{16,}={0,2})(?::([A-Za-z0-9+\/]{16,}={0,2}))?$/';
const EMBEDDED_RE = '/(?<![A-Za-z0-9+\/:\\\\])(\d{1,2}):3:((?:[A-Za-z0-9+\/]|\\\\\/){40,}={0,2})/';
const SQL_PREFILTER = "(`%1\$s` REGEXP '^[0-9]{1,2}:[0-3]:' OR `%1\$s` LIKE '%%:3:%%')";
const TEXT_TYPES = ['varchar','char','text','tinytext','mediumtext','longtext','json','blob','tinyblob','mediumblob','longblob','varbinary','binary'];

/** Magento's cipher versions: the SECOND number of every ciphertext prefix. */
const CIPHERS = [
    0 => ['mcrypt Blowfish',                  'mcrypt', 'Magento 1 and the earliest Magento 2'],
    1 => ['mcrypt Rijndael-128 CBC',          'mcrypt', 'Magento 2.0'],
    2 => ['mcrypt Rijndael-256 CBC',          'mcrypt', 'Magento 2.0 - 2.1'],
    3 => ['libsodium ChaCha20-Poly1305 IETF', 'sodium', 'Magento 2.1 and later (current)'],
];
/** cipher 3 payload = 12-byte nonce + 16-byte Poly1305 tag + plaintext, so 28 bytes is the floor. */
const SODIUM_OVERHEAD = 28;
const KEY_BYTES = 32;

$command = $argv[1] ?? '';
$opt = ['magento-root' => __DIR__, 'tables' => '', 'exclude' => '', 'max-rows' => '0', 'apply' => false,
        'dump' => '', 'old-key' => '', 'limit' => '0', 'allow-binary' => false, 'show-all' => false,
        'no-color' => false, 'reveal' => false, 'value' => '', 'table' => '', 'column' => '', 'id' => '',
        'key' => '', 'key-line' => '', 'stdin' => false];
foreach (array_slice($argv, 2) as $a) {
    if (preg_match('/^--([a-z-]+)(?:=(.*))?$/s', $a, $m)) { $opt[$m[1]] = $m[2] ?? true; }
}
/**
 * Decrypting legacy mcrypt values goes through a pure-PHP polyfill that holds on to compiled code,
 * so a store with a few hundred of them runs out of headroom under the 128M CLI default and dies
 * mid-report. Raise the ceiling to 512M unless the environment already allows more.
 */
$memWas = trim((string)ini_get('memory_limit'));
$memBytes = (int)$memWas * (stripos($memWas, 'G') ? 1073741824 : (stripos($memWas, 'M') ? 1048576 : (stripos($memWas, 'K') ? 1024 : 1)));
if ($memWas !== '-1' && $memBytes < 536870912) { @ini_set('memory_limit', '512M'); }
$memNow = trim((string)ini_get('memory_limit'));

$GLOBALS['color'] = !($opt['no-color'] === true || getenv('NO_COLOR') !== false)
    && (function_exists('stream_isatty') ? @stream_isatty(STDOUT) : false);

if (!in_array($command, ['scan', 'explain', 'encrypt', 'code-scan', 're-encrypt', 'verify', 'retire-keys'], true)) {
    fwrite(STDERR, usageText());
    exit(2);
}
$root = rtrim((string)$opt['magento-root'], '/');
if (!is_file("$root/app/etc/env.php")) { fwrite(STDERR, "no app/etc/env.php under $root - run from the Magento root or pass --magento-root=PATH\n"); exit(2); }

// A fatal (memory exhaustion on a large store, most likely) truncates the report after the last
// table it managed to print. Without this, that truncation is silent and looks like a clean finish.
register_shutdown_function(function (): void {
    $e = error_get_last();
    if (!$e || !in_array($e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR], true)) return;
    $msg = "\n" . str_repeat('!', 100) . "\n"
         . " REPORT INCOMPLETE - this run stopped early and the tables above are NOT the whole database.\n"
         . ' ' . trim($e['message']) . "\n"
         . " Do not treat the counts above as a full inventory, and do not retire any key on the strength of them.\n";
    if (strpos($e['message'], 'memory') !== false) {
        $msg .= " Re-run with more memory, for example:  php -d memory_limit=1G " . basename(__FILE__) . " ...\n"
              . " Or narrow the run with --tables=a,b or --max-rows=N and work through the database in parts.\n";
    }
    $msg .= str_repeat('!', 100) . "\n";
    fwrite(STDOUT, $msg);
});

function usageText(): string
{
    return <<<TXT
usage: php magento-key-rotation.php COMMAND [--options]

COMMANDS
  scan          report every encrypted value in the database, per table and column,
                and diagnose every value that cannot be decrypted
  explain       decode one ciphertext: what its prefix means and why it does or does
                not decrypt      --value='0:3:...'   or   --table=T --column=C --id=N
  encrypt       encrypt one value, to paste into a row by hand
                --value=SECRET (or --stdin)  [--key=KEY] [--key-line=N]
  code-scan     which extensions use Magento's encryptor and which roll their own crypto
  re-encrypt    move every value onto the newest key in env.php (dry run without --apply)
  verify        exit 0 only when nothing readable still depends on an older key
  retire-keys   overwrite the older keys in env.php, keeping the line positions

COMMON OPTIONS
  --magento-root=PATH   default: the directory of this script
  --tables=a,b          restrict to these tables      --exclude=a,b   skip these tables
  --max-rows=N          skip tables with more than N estimated rows (0 = no limit)
  --old-key=KEY         extra key to try for values whose key is no longer in env.php
  --show-all            list every problem value, not just the first few of each kind
  --no-color            plain output

RE-ENCRYPT OPTIONS
  --apply               actually write; without it nothing in the database changes
  --dump=FILE           write the UPDATE statements to FILE (reverse: FILE.backup.sql)
  --limit=N             stop after N rows
  --allow-binary        also re-encrypt values whose plaintext is not printable text

Start with:  php magento-key-rotation.php scan

TXT;
}

/* ---------- output ---------- */
function say(string $s = ''): void { echo $s, "\n"; }
function c(string $s, string $code): string { return $GLOBALS['color'] ? "\033[{$code}m{$s}\033[0m" : $s; }
function bold(string $s): string { return c($s, '1'); }
function dim(string $s): string { return c($s, '2'); }
function red(string $s): string { return c($s, '31;1'); }
function yellow(string $s): string { return c($s, '33'); }
function green(string $s): string { return c($s, '32'); }
function cyan(string $s): string { return c($s, '36'); }
function rule(string $ch = '-'): void { say(dim(str_repeat($ch, 100))); }
function heading(string $title): void { say(''); rule('='); say(bold(' ' . $title)); rule('='); }
function section(string $title): void { say(''); say(bold(' ' . $title)); rule(); }
function field(string $label, string $value): void { printf(" %-17s %s\n", $label, $value); }
/** Wrap prose to the terminal width with a hanging indent, so long help never turns into one long line. */
function wrap(string $text, string $indent = '      ', ?string $firstIndent = null): void
{
    $width = max(60, (int)(getenv('COLUMNS') ?: 100)) - strlen($indent);
    $first = $firstIndent ?? $indent;
    foreach (explode("\n", wordwrap($text, $width, "\n", false)) as $i => $line) {
        say(($i === 0 ? $first : $indent) . $line);
    }
}

/* ---------- keys ---------- */
/** Raw 32 bytes behind an env.php key line, or null when the line is not a usable key. */
function keyMaterial(string $raw): ?string
{
    $k = trim($raw);
    if (strpos($k, 'retired-') === 0) return null;
    if (strpos($k, 'base64') === 0) {
        $d = base64_decode((string)preg_replace('/^base64:?/', '', $k), true);
        if ($d === false) return null;
        $k = $d;
    }
    return strlen($k) === KEY_BYTES ? $k : null;
}
/** Short stable identifier for a key, safe to print and to compare between environments. */
function keyFingerprint(string $material): string { return substr(hash('sha256', $material), 0, 8); }
function keyLineDescription(int $i, string $raw, int $latest): string
{
    $label = sprintf('key%-2d', $i);
    if (strpos(trim($raw), 'retired-') === 0) return sprintf('%s %-16s %s', $label, 'retired', yellow('RETIRED by this script - decrypts nothing, line kept on purpose'));
    $material = keyMaterial($raw);
    $format = strpos(trim($raw), 'base64') === 0 ? 'base64 (2.4.7+)' : 'legacy 32-char';
    if ($material === null) {
        return sprintf('%s %-16s %s', $label, $format, red(sprintf('UNUSABLE - this line is not a %d-byte key; check env.php for a truncated or wrapped value', KEY_BYTES)));
    }
    $note = $i === $latest ? green('<- LATEST: everything is re-encrypted to this key') : dim('older key');
    return sprintf('%s %-16s fp %s  %s', $label, $format, cyan(keyFingerprint($material)), $note);
}

/* ---------- ciphertext anatomy ---------- */
/** Split "key:cipher:payload" (or the 4-part mcrypt form "key:cipher:iv:payload"). */
function parseCipher(string $v): ?array
{
    if (!preg_match(WHOLE_RE, $v, $m)) return null;
    $hasIv = isset($m[4]) && $m[4] !== '';
    return ['key' => (int)$m[1], 'version' => (int)$m[2], 'iv' => $hasIv ? $m[3] : null, 'data' => $hasIv ? $m[4] : $m[3]];
}
function cipherName(int $v): string { return CIPHERS[$v][0] ?? 'unknown cipher version'; }
function cipherEra(int $v): string { return CIPHERS[$v][2] ?? 'unknown'; }
function mcryptAvailable(): bool { return function_exists('mcrypt_decrypt') || function_exists('mdecrypt_generic'); }
/** How the prefix of one value reads in plain English. */
function prefixExplanation(array $p, array $keys, int $latest): array
{
    $n = count($keys);
    $keyLine = $p['key'] < $n
        ? sprintf('key line %d of crypt/key in app/etc/env.php%s', $p['key'], $p['key'] === $latest ? ' (the latest key)' : ' (an older key)')
        : sprintf('key line %d - which does NOT exist: env.php holds %d line(s), 0 to %d', $p['key'], $n, $n - 1);
    return [
        sprintf('%d = %s', $p['key'], $keyLine),
        sprintf('%d = cipher version %d: %s, used by %s', $p['version'], $p['version'], cipherName($p['version']), cipherEra($p['version'])),
        sprintf('    %s', $p['version'] === 3
            ? 'authenticated, so a wrong key fails outright instead of returning garbage'
            : 'NOT authenticated, so a wrong key returns garbage instead of an error'),
    ];
}
/** Printable text (UTF-8, allowing tab/newline) is what every real secret looks like; anything else is suspect. */
function looksLikeText(string $s): bool
{
    return $s !== '' && preg_match('/^[\x09\x0A\x0D\x20-\x7E\x{80}-\x{10FFFF}]*$/u', $s) === 1;
}
/** Name what a non-text plaintext actually is, so the user can judge it instead of guessing. */
function describeBytes(string $s): string
{
    $signatures = ["\x1f\x8b" => 'gzip data', "PK\x03\x04" => 'zip archive', "\x30\x82" => 'DER/ASN.1, a certificate or private key',
                   "\xff\xd8\xff" => 'JPEG image', "\x89PNG" => 'PNG image', "BZh" => 'bzip2 data', "x\x9c" => 'zlib data'];
    foreach ($signatures as $magic => $name) {
        if (strncmp($s, $magic, strlen($magic)) === 0) return sprintf('%s, %d bytes', $name, strlen($s));
    }
    $printable = strlen((string)preg_replace('/[^\x09\x0A\x0D\x20-\x7E]/', '', $s));
    $pct = strlen($s) ? (int)round($printable / strlen($s) * 100) : 0;
    $shape = $pct >= 85 ? 'almost all printable but not valid UTF-8, so a charset or truncation problem' : ($pct <= 40 ? 'no recognisable structure, the shape of random bytes' : 'part text, part binary');
    return sprintf('%d bytes, %d%% printable, %s [%s]', strlen($s), $pct, $shape, substr(bin2hex(substr($s, 0, 8)), 0, 16));
}

/* ---------- diagnosis: WHY a value does not decrypt ---------- */
/**
 * Which OTHER key line in env.php reads this value, if any? Asked by rewriting the key prefix and
 * letting Magento decrypt, so its own cipher and IV handling is reused rather than reimplemented.
 * For the unauthenticated mcrypt ciphers the answer only counts when the output is real text.
 */
function keyLineThatReads(string $cipher, array $p): ?int
{
    global $encryptor, $keys, $retiredIdx;
    // The pure-PHP mcrypt polyfill compiles and keeps code on every decryption, so probing each of
    // several hundred legacy values would exhaust memory. Whether another key line reads them is a
    // property of the key, not of one row, so for the mcrypt ciphers a few samples per prefix settle
    // it and the answer is reused. Cipher 3 is libsodium: cheap, and it keeps nothing.
    static $sampled = [];
    $slot = $p['key'] . ':' . $p['version'];
    $budgeted = $p['version'] !== 3;
    if ($budgeted && ($sampled[$slot]['n'] ?? 0) >= 3) return $sampled[$slot]['found'];
    $found = null;
    foreach (array_keys($keys) as $i) {
        if ($i === $p['key'] || isset($retiredIdx[$i]) || keyMaterial($keys[$i]) === null) continue;
        try { $try = $encryptor->decrypt(preg_replace('/^\d{1,2}:/', $i . ':', $cipher, 1)); }
        catch (Throwable $e) { continue; }
        if (is_string($try) && $try !== '' && ($p['version'] === 3 || looksLikeText($try))) { $found = $i; break; }
    }
    if ($budgeted) $sampled[$slot] = ['n' => ($sampled[$slot]['n'] ?? 0) + 1, 'found' => $found];
    return $found;
}

/**
 * One attempt to read a ciphertext, with a named reason when it fails.
 * Returns ['plain'=>?string, 'code'=>?string, 'x'=>array of facts for the report].
 * A null code means success. Codes are explained by problemHelp().
 */
function attempt(string $cipher, bool $allowBinary, array $ctx = []): array
{
    global $encryptor, $oldKeyFallback, $keys, $retiredIdx, $keyAdapters, $latestKey;

    $p = parseCipher($cipher);
    $x = ['cipher' => $cipher, 'len' => strlen($cipher)] + $ctx;
    if ($p === null) return ['plain' => null, 'code' => 'MALFORMED', 'x' => $x];
    $x += ['key' => $p['key'], 'version' => $p['version']];

    $raw = base64_decode($p['data'], true);
    if ($raw === false) return ['plain' => null, 'code' => 'PAYLOAD_NOT_BASE64', 'x' => $x];
    $x['bytes'] = strlen($raw);

    $x['keys'] = count($keys);

    // Magento's own encryptor first: it is the definition of "can Magento read this".
    // A prefix pointing past the last key line is not handed to it: older Magento versions warn on that.
    $plain = '';
    if ($p['key'] < count($keys)) {
        try { $plain = $encryptor->decrypt($cipher); } catch (Throwable $e) { $plain = ''; $x['error'] = $e->getMessage(); }
    }
    if (($plain === '' || $plain === false) && $oldKeyFallback && $p['version'] === 3) {
        try { $plain = $oldKeyFallback->decrypt($raw); $x['via'] = '--old-key'; } catch (Throwable $e) { $plain = ''; }
    }

    if (is_string($plain) && $plain !== '') {
        if ($allowBinary || looksLikeText($plain)) return ['plain' => $plain, 'code' => null, 'x' => $x];
        $x['shape'] = describeBytes($plain);
        // Cipher 3 verifies a Poly1305 tag: non-empty output PROVES the key was right and these bytes
        // are the original plaintext. Only the unauthenticated mcrypt ciphers can return garbage.
        if ($p['version'] === 3) return ['plain' => $plain, 'code' => 'BINARY_PLAINTEXT', 'x' => $x];
        if (($found = keyLineThatReads($cipher, $p)) !== null) { $x['found_on'] = $found; return ['plain' => null, 'code' => 'KEY_INDEX_SHIFTED', 'x' => $x]; }
        return ['plain' => $plain, 'code' => 'LEGACY_GARBAGE', 'x' => $x];
    }

    /* nothing came back - work out which of the several possible reasons it is */
    if ($p['version'] !== 3) {
        if (mcryptAvailable() && ($found = keyLineThatReads($cipher, $p)) !== null) { $x['found_on'] = $found; return ['plain' => null, 'code' => 'KEY_INDEX_SHIFTED', 'x' => $x]; }
        return ['plain' => null, 'code' => mcryptAvailable() ? 'LEGACY_WRONG_KEY' : 'MCRYPT_MISSING', 'x' => $x];
    }
    if (isset($retiredIdx[$p['key']])) return ['plain' => null, 'code' => 'KEY_RETIRED', 'x' => $x];
    if (strlen($raw) < SODIUM_OVERHEAD) return ['plain' => null, 'code' => 'PAYLOAD_TRUNCATED', 'x' => $x];

    // Does ANY other line in env.php read it? If so the key lines were reordered or one was
    // removed, which is a different problem with a different fix from "the key is gone".
    if (($found = keyLineThatReads($cipher, $p)) !== null) { $x['found_on'] = $found; return ['plain' => null, 'code' => 'KEY_INDEX_SHIFTED', 'x' => $x]; }
    if ($p['key'] >= count($keys)) return ['plain' => null, 'code' => 'KEY_LINE_MISSING', 'x' => $x];
    if (keyMaterial($keys[$p['key']]) === null) { $x['keyline'] = $keys[$p['key']]; return ['plain' => null, 'code' => 'KEY_LINE_UNUSABLE', 'x' => $x]; }
    // An empty plaintext and a failed decryption look identical through Magento's API; ask sodium directly.
    if (isset($keyAdapters[$p['key']])) {
        try {
            $direct = $keyAdapters[$p['key']]->decrypt($raw);
            if ($direct === '') {
                $n = SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES;
                $nonce = substr($raw, 0, $n);
                $ok = @sodium_crypto_aead_chacha20poly1305_ietf_decrypt(substr($raw, $n), $nonce, $nonce, keyMaterial($keys[$p['key']]));
                if ($ok === '') return ['plain' => '', 'code' => 'EMPTY_PLAINTEXT', 'x' => $x];
            }
        } catch (Throwable $e) { /* fall through to KEY_MISMATCH */ }
    }
    if (isset($x['column_limit'])) return ['plain' => null, 'code' => 'PAYLOAD_TRUNCATED', 'x' => $x];
    return ['plain' => null, 'code' => 'KEY_MISMATCH', 'x' => $x];
}

/**
 * A value that starts like a ciphertext but does not parse. Without this the scan would skip it
 * in silence, which is the worst outcome: mangled secrets look exactly like absent ones.
 */
function classifyMangled(string $v): array
{
    preg_match('/^(\d{1,2}):([0-3]):(.*)$/s', $v, $m);
    $x = ['cipher' => $v, 'len' => strlen($v), 'key' => (int)$m[1], 'version' => (int)$m[2]];
    $tail = $m[3];
    $raw = preg_match('%[^A-Za-z0-9+/=]%', $tail) ? false : base64_decode($tail, true);
    if ($raw === false) return ['PAYLOAD_NOT_BASE64', $x];
    $x['bytes'] = strlen($raw);
    if ((int)$m[2] === 3 && strlen($raw) < SODIUM_OVERHEAD) return ['PAYLOAD_TRUNCATED', $x];
    return ['MALFORMED', $x];
}

/** Dead data: nothing readable is lost by retiring the key it names, so it does not gate retire-keys. */
function isDead(?string $code): bool
{
    return in_array($code, ['MALFORMED', 'PAYLOAD_NOT_BASE64', 'PAYLOAD_TRUNCATED', 'KEY_RETIRED', 'LEGACY_GARBAGE'], true);
}
/**
 * Narrower than isDead(): may this row be offered for deletion in .unreadable.sql?
 * KEY_RETIRED is deliberately excluded - restoring the real key to that line brings the value back,
 * and retire-keys itself leaves an env.php backup that may still hold it.
 */
function isClearable(?string $code): bool
{
    return in_array($code, ['MALFORMED', 'PAYLOAD_NOT_BASE64', 'PAYLOAD_TRUNCATED', 'LEGACY_GARBAGE'], true);
}

/**
 * For each failure code: a headline, why it happened, and what to do about it.
 * $x carries the facts collected by attempt() so the text can be specific rather than generic.
 */
function problemHelp(string $code, array $x): array
{
    $k = $x['key'] ?? 0; $v = $x['version'] ?? 3; $php = PHP_VERSION;
    // The shape was measured on one sampled value; say so when the group holds more than one.
    $shape = ($x['shape'] ?? 'binary');
    $shape = (($x['count'] ?? 1) > 1) ? 'one of them decrypts to ' . $shape : 'the output is ' . $shape;
    switch ($code) {
        case 'MCRYPT_MISSING': return [
            'Encrypted with mcrypt, and this PHP cannot run mcrypt',
            sprintf('Cipher version %d is %s, used by %s. PHP removed the mcrypt extension in 7.2 and this is PHP %s, so these values cannot be decrypted here at all. The key on line %d is probably fine; the algorithm is what is missing.', $v, cipherName($v), cipherEra($v), $php, $k),
            ['Bring mcrypt back on a COPY of the site, then re-run this script there: composer require phpseclib/mcrypt_compat (pure PHP, no extension needed) or pecl install mcrypt. The values come back as cipher 3 on the newest key, and you move the fixed rows across.',
             'Or decide the data is expendable. Legacy saved cards, dead API sessions and abandoned quotes usually are. re-encrypt --dump=FILE writes FILE.unreadable.sql, which NULLs exactly these columns after you review it.',
             'Do not delete the old key lines from env.php to tidy up. The first number of the prefix is a line position, so removing a line renumbers every key after it.'],
        ];
        case 'LEGACY_WRONG_KEY': return [
            'mcrypt value that will not decrypt with the key on its line',
            sprintf('Cipher version %d (%s) has no integrity check, so it cannot report a wrong key. mcrypt is available here and it still produced nothing usable, which points at the key on line %d not being the key this value was written with.', $v, cipherName($v), $k),
            [sprintf('Find the env.php that was live when this row was written and put its key back on line %d, keeping the line order.', $k),
             '--old-key only helps cipher 3 (sodium); for mcrypt values the key has to be on the right line in env.php.',
             'If the key is genuinely lost, the plaintext is gone. Rotate that secret at its source and re-enter it in the admin.'],
        ];
        case 'KEY_LINE_MISSING': return [
            'The value points at a key line that does not exist',
            sprintf('The prefix says key line %d, but crypt/key in env.php holds %d line(s), numbered 0 to %d. Key lines were deleted. Every ciphertext stores a POSITION, so removing one line silently renumbers all the keys after it.', $k, $x['keys'] ?? 0, max(0, ($x['keys'] ?? 1) - 1)),
            ['Restore crypt/key from a backup of env.php taken before the lines were removed, with the same number of lines in the same order. This is the whole repair - no data has to change.',
             'From then on retire a key by overwriting its value in place (retire-keys does that) and never by deleting the line.'],
        ];
        case 'KEY_RETIRED': return [
            'The key on that line was retired',
            sprintf('Line %d in env.php was overwritten with a "retired-" placeholder, so by design it decrypts nothing. Anything still labelled %d:%d was missed when the data was re-encrypted, before the key was retired.', $k, $k, $v),
            [sprintf('If the value still matters, put the real key back on line %d (the position is what counts, not the order you found it in) and run re-encrypt again.', $k),
             'If it does not, this is dead ciphertext. It blocks nothing and verify still passes with it in place. It is deliberately NOT offered for deletion, because putting the old key back on that line is all it takes to read it again.'],
        ];
        case 'KEY_INDEX_SHIFTED': return [
            'Right key, wrong line: env.php key lines were reordered',
            sprintf('The value is labelled key line %d%s, but it decrypts cleanly with the key on line %d. A key line was inserted, removed or reordered, so the positions no longer line up with what was stored. Magento itself will fail on these values in the storefront and admin, not just this script.',
                $k, isset($x['keys']) && $k >= $x['keys'] ? sprintf(' - a line that does not even exist, env.php has %d', $x['keys']) : '', $x['found_on'] ?? 0),
            [sprintf('Repair env.php: put the keys back in their original order so the key that reads this value sits on line %d again. Then re-run scan; these disappear.', $k),
             sprintf('If reordering is not possible, pass --old-key=<the key currently on line %d> and re-encrypt will pick these values up and move them to the latest key.', $x['found_on'] ?? 0),
             'Do this before anything else. Every value written after the shift is affected, not only the ones listed here.'],
        ];
        case 'KEY_MISMATCH': return [
            'No key in env.php can decrypt this value',
            sprintf('Cipher 3 is authenticated: it either returns the exact original bytes or nothing. None of the keys in env.php returned anything, so this value was written with a key that is not there any more. Usual causes: env.php copied from another environment, a key regenerated instead of appended, or the database restored from a different site.', $k),
            ['Find the key that wrote it (an older env.php, a deployment secret store, the backup taken before the last rotation) and pass --old-key=THAT_KEY. re-encrypt then moves these values onto the latest key.',
             'If the key cannot be found the plaintext is unrecoverable by any means. Rotate that secret at its source (payment gateway, SMTP, API provider) and re-enter it in the admin, then clear the stale rows.'],
        ];
        case 'KEY_LINE_UNUSABLE': return [
            'The key line it points at is not a valid key',
            sprintf('Line %d of crypt/key does not decode to a %d-byte key. A truncated paste, a stray quote or a wrapped line in env.php will do this.', $k, KEY_BYTES),
            [sprintf('Open app/etc/env.php and check line %d of crypt/key: a legacy key is exactly %d characters, a 2.4.7+ key starts with "base64" and decodes to %d bytes.', $k, KEY_BYTES, KEY_BYTES),
             'Keys are separated by newlines inside one string; make sure nothing else was inserted between them.'],
        ];
        case 'PAYLOAD_TRUNCATED': return [
            'The ciphertext is cut short',
            isset($x['column_limit'])
                ? sprintf('The stored string is exactly %d characters, the full width of the column, and its authentication tag does not check out. That is what a ciphertext cut off on write looks like: encryption makes a value roughly 40%% longer, so a column sized for the plaintext silently truncates it.', $x['column_limit'])
                : sprintf('The payload decodes to %d bytes. A cipher 3 value needs at least %d before any plaintext at all: a 12-byte nonce plus a 16-byte authentication tag. Bytes are missing from what is stored.', $x['bytes'] ?? 0, SODIUM_OVERHEAD),
            ['Widen the column, then re-enter the secret in the admin so a full-length ciphertext is written.',
             'The missing bytes are not recoverable from this row. Restore it from a backup taken before it was written, or re-enter the secret in the admin.',
             'Report the column to the extension vendor if it is not a core table: this row will be truncated again the next time it is written.'],
        ];
        case 'PAYLOAD_NOT_BASE64': return [
            'The payload is not valid base64 any more',
            'The part after the prefix contains characters outside the base64 alphabet, so it never reaches the cipher. The stored text was mangled rather than mis-encrypted: a dump imported with the wrong charset, an editor that "fixed" the string, or double escaping.',
            ['Restore the row from a backup taken before the export or import that mangled it.',
             'Check how the database is being dumped and loaded. mysqldump without --default-character-set=utf8mb4, or a spreadsheet round trip, both do this.'],
        ];
        case 'MALFORMED': return [
            'Does not have the shape of a Magento ciphertext',
            'A Magento value looks like key:cipher:base64, for example 0:3:xxxxx. This value matched the search but does not parse, so it is probably ordinary data that happens to start with digits and colons.',
            ['Nothing to do in most cases. Use --exclude=TABLE to keep the column out of the report if it is a known false positive.'],
        ];
        case 'BINARY_PLAINTEXT': return [
            'Decrypts correctly, but the secret itself is binary',
            sprintf('This is NOT a failure. Cipher 3 verifies an authentication tag, so getting bytes back proves the key on line %d is right and these are the original bytes. They are simply not printable text: %s. Some modules store certificates, keys or compressed blobs encrypted.', $k, $shape),
            ['Re-encrypt them: re-encrypt --allow-binary. That is safe here precisely because the tag verified.',
             'Without --allow-binary the script leaves them on the old key, and that alone will keep verify failing and block retire-keys.'],
        ];
        case 'LEGACY_GARBAGE': return [
            'mcrypt value that decrypts to garbage: the wrong key',
            sprintf('Cipher %d (%s) has no authentication tag, so a wrong key returns plausible-looking rubbish instead of an error: %s, which is what a wrong key produces, not a real secret. The key that wrote these is not on line %d any more.', $v, cipherName($v), $shape, $k),
            ['Do NOT pass --allow-binary for these. It would re-encrypt the rubbish onto the new key and destroy the evidence of what went wrong.',
             sprintf('If the original key still exists, put it on line %d in env.php and re-run. Otherwise treat the value as lost, rotate the secret at its source, and clear the row.', $k)],
        ];
        case 'EMPTY_PLAINTEXT': return [
            'Decrypts to an empty string',
            'The key is right and the plaintext is genuinely empty. Magento returns an empty string both for "decryption failed" and for "the secret was empty", which is why these normally show up as failures; a direct check confirmed this one really is empty.',
            ['Nothing is at risk: there is no secret to lose either way.',
             're-encrypt moves it onto the latest key like any other value, which is what clears the old key prefix off the row.'],
        ];
    }
    return [$code, 'No description available for this code.', []];
}

/* ---------- problem collection and reporting ---------- */
$PROBLEMS = [];
function recordProblem(string $code, array $x, string $table, string $col, string $where, string $value): void
{
    global $PROBLEMS;
    if (!isset($PROBLEMS[$code])) $PROBLEMS[$code] = ['count' => 0, 'columns' => [], 'samples' => [], 'x' => $x];
    $PROBLEMS[$code]['count']++;
    $PROBLEMS[$code]['columns']["$table.$col"] = ($PROBLEMS[$code]['columns']["$table.$col"] ?? 0) + 1;
    if (count($PROBLEMS[$code]['samples']) < 500) {
        $PROBLEMS[$code]['samples'][] = ['t' => $table, 'c' => $col, 'w' => $where, 'v' => $value, 'x' => $x];
    }
}
/** The prefix legend. Printed only when something went wrong - a clean run does not need it. */
function printCiphertextLegend(array $keys, int $latest): void
{
    section('HOW TO READ A MAGENTO ENCRYPTED VALUE');
    say('   ' . cyan('0') . ':' . yellow('3') . ':' . dim('ZGVtb25zdHJhdGlvbiBwYXlsb2FkLi4u'));
    say('   ' . cyan('|') . ' ' . yellow('|') . ' ' . dim('|'));
    say('   ' . cyan('|') . ' ' . yellow('|') . ' ' . dim('+- the secret, base64: a 12-byte random nonce, a 16-byte authentication tag,'));
    say('   ' . cyan('|') . ' ' . yellow('|') . '    ' . dim('then the encrypted bytes'));
    say('   ' . cyan('|') . ' ' . yellow('+--- cipher version') . ': 0 Blowfish, 1 Rijndael-128, 2 Rijndael-256 - all mcrypt,');
    say('   ' . cyan('|') . '      which PHP removed in 7.2, none of them authenticated. 3 is libsodium');
    say('   ' . cyan('|') . '      ChaCha20-Poly1305, the current one: a wrong key fails outright instead');
    say('   ' . cyan('|') . '      of returning garbage.');
    say('   ' . cyan('+----- key line') . ': the POSITION of the key inside crypt/key in app/etc/env.php,');
    say('          counting from 0. It is a line number, not a key id. Delete a key line and');
    say('          every key after it shifts up, so every value that pointed at them becomes');
    say('          unreadable. That is why this script retires a key by overwriting it in place.');
    say('');
    field('This site', sprintf('%d key line(s), 0 to %d, latest is key%d - values already reading %d:3 are done.', count($keys), count($keys) - 1, $latest, $latest));
}
function printProblemReport(array $keys, int $latest, bool $showAll, string $dump, bool $brief = false): void
{
    global $PROBLEMS;
    if (!$PROBLEMS) return;
    $total = array_sum(array_column($PROBLEMS, 'count'));
    printCiphertextLegend($keys, $latest);
    heading(sprintf('VALUES NEEDING ATTENTION: %d value(s), %d distinct cause(s)', $total, count($PROBLEMS)));
    uasort($PROBLEMS, fn($a, $b) => $b['count'] <=> $a['count']);
    $n = 0;
    foreach ($PROBLEMS as $code => $p) {
        $n++;
        [$title, $why, $fixes] = problemHelp($code, $p['x'] + ['count' => $p['count']]);
        $isInfo = in_array($code, ['BINARY_PLAINTEXT', 'EMPTY_PLAINTEXT', 'MALFORMED'], true);
        say('');
        say(sprintf(' %s %s %s', bold("[$n]"), $isInfo ? yellow($title) : red($title), dim("($code, " . $p['count'] . ' value' . ($p['count'] === 1 ? '' : 's') . ')')));
        wrap($why, '     ', '     ');
        if (!$brief) {
        say('');
        say(dim('     WHERE'));
        arsort($p['columns']);
        foreach (array_slice($p['columns'], 0, $showAll ? 999 : 8, true) as $col => $cnt) {
            say(sprintf('       %-58s %d value%s', $col, $cnt, $cnt === 1 ? '' : 's'));
        }
        if (!$showAll && count($p['columns']) > 8) say(dim(sprintf('       ... and %d more column(s), --show-all lists them', count($p['columns']) - 8)));
        $samples = $showAll ? $p['samples'] : array_slice($p['samples'], 0, 3);
        if ($samples) { say(''); say(dim('     EXAMPLES')); }
        foreach ($samples as $s) {
            say(sprintf('       %s  %s', dim($s['t'] . '.' . $s['c'] . ' ' . $s['w']), substr($s['v'], 0, 46) . (strlen($s['v']) > 46 ? '...' : '') . dim(' (' . strlen($s['v']) . ' chars)')));
        }
        if (!$showAll && $p['count'] > count($samples)) say(dim(sprintf('       ... %d more, --show-all lists every one', $p['count'] - count($samples))));
        }
        say('');
        say(dim('     WHAT TO DO'));
        foreach ($fixes as $i => $f) wrap($f, '           ', sprintf('       %d.  ', $i + 1));
        if (isClearable($code) && $dump !== '') wrap(sprintf('These are listed in %s.unreadable.sql, which clears them once you have reviewed it.', $dump), '           ', '       ->  ');
    }
}

/* ---------- schema helpers ---------- */
function columns(PDO $pdo, string $schema, array $only, array $skip, int $maxRows): array
{
    $sql = "SELECT c.TABLE_NAME t, c.COLUMN_NAME c, c.DATA_TYPE d, c.CHARACTER_MAXIMUM_LENGTH len, IFNULL(tb.TABLE_ROWS,0) r
            FROM information_schema.COLUMNS c JOIN information_schema.TABLES tb
              ON tb.TABLE_SCHEMA=c.TABLE_SCHEMA AND tb.TABLE_NAME=c.TABLE_NAME
            WHERE c.TABLE_SCHEMA=? AND tb.TABLE_TYPE='BASE TABLE' AND c.DATA_TYPE IN ('" . implode("','", TEXT_TYPES) . "')
            ORDER BY c.TABLE_NAME, c.COLUMN_NAME";
    $st = $pdo->prepare($sql); $st->execute([$schema]);
    $out = [];
    foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) {
        if ($only && !in_array($r['t'], $only, true)) continue;
        if ($skip && in_array($r['t'], $skip, true)) continue;
        $out[] = $r + ['skipped' => ($maxRows > 0 && (int)$r['r'] > $maxRows)];
    }
    return $out;
}
function primaryKey(PDO $pdo, string $schema, string $table): array
{
    $st = $pdo->prepare("SELECT COLUMN_NAME FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=? AND TABLE_NAME=? AND CONSTRAINT_NAME='PRIMARY' ORDER BY ORDINAL_POSITION");
    $st->execute([$schema, $table]);
    return array_column($st->fetchAll(PDO::FETCH_ASSOC), 'COLUMN_NAME');
}
/** Human pointer to one row, for the problem list: the primary key when there is one. */
function rowWhere(array $row, array $pk): string
{
    if (!$pk) return '(no primary key)';
    $parts = [];
    foreach ($pk as $p) $parts[] = $p . '=' . (string)($row[$p] ?? '?');
    return implode(', ', $parts);
}
/** Re-encrypt every embedded occurrence inside a larger value; returns [newValue, replaced, failed]. */
function reencryptEmbedded(string $value, int $latestKey, bool $allowBinary, array $ctx): array
{
    $replaced = 0; $failed = 0;
    $new = preg_replace_callback(EMBEDDED_RE, function ($m) use (&$replaced, &$failed, $latestKey, $allowBinary, $ctx) {
        global $encryptor;
        if ((int)$m[1] === $latestKey) return $m[0];
        $escaped = strpos($m[2], '\\/') !== false;
        $cipher = $m[1] . ':3:' . ($escaped ? str_replace('\\/', '/', $m[2]) : $m[2]);
        $res = attempt($cipher, $allowBinary, ['embedded' => true]);
        if ($res['code'] !== null && $res['code'] !== 'EMPTY_PLAINTEXT') {
            $failed++;
            if ($ctx) recordProblem($res['code'], $res['x'], $ctx['t'], $ctx['c'] . ' (embedded)', $ctx['w'], $cipher);
            return $m[0];
        }
        $fresh = $encryptor->encrypt((string)$res['plain']);
        $replaced++;
        return $escaped ? str_replace('/', '\\/', $fresh) : $fresh;
    }, $value);
    // Serialized PHP strings carry a byte length: s:44:"...";  fix any that changed (key number 9 -> 10).
    $new = preg_replace_callback('/s:(\d+):"(\d{1,2}:3:[A-Za-z0-9+\/=]+)"/', fn($m) => 's:' . strlen($m[2]) . ':"' . $m[2] . '"', $new);
    return [$new, $replaced, $failed];
}
/**
 * Does this value's PLAINTEXT contain further ciphertext on an older key?
 *
 * Magento's 2FA config is stored that way: tfa_user_config.encoded_config is one ciphertext whose
 * plaintext holds a second one for the TOTP secret. On disk the inner value exists only inside the
 * outer, so no scan of the database can see it. Rotating moves the outer and silently leaves the
 * inner naming the old key, and nothing fails until that key is retired, at which point every
 * affected admin is locked out. Returns the older key lines found inside, or an empty array.
 */
function nestedOnOldKey(string $value, int $latestKey): array
{
    // A plaintext needs about 44 characters to hold even the shortest nested value, so anything
    // whose payload is too small to contain that is skipped without being decrypted at all.
    if (!preg_match(WHOLE_RE, $value, $m) || strlen($m[3]) < 96) return [];
    // Through attempt(), so --old-key opens the outer value here exactly as it does everywhere else.
    $res = attempt($value, true, []);
    $plain = (string)($res['plain'] ?? '');
    if ($plain === '' || strpos($plain, ':3:') === false) return [];
    if (!preg_match_all(EMBEDDED_RE, $plain, $all)) return [];
    $old = [];
    foreach ($all[1] as $k) {
        if ((int)$k !== $latestKey) $old[] = (int)$k;
    }
    return $old;
}

function codeScan(string $root): int
{
    $magento = '/EncryptorInterface|\\\\Encryptor\b|encryptor->(encrypt|decrypt)\(|Backend\\\\Encrypted/';
    $own = '/openssl_(encrypt|decrypt)|sodium_crypto_(secretbox|aead_[a-z0-9_]+_(encrypt|decrypt)|box)|mcrypt_(encrypt|decrypt)|Defuse\\\\Crypto|phpseclib\d*\\\\Crypt\\\\(AES|Rijndael|RSA|DES|Blowfish)|\bAES::|new \\\\?Crypt_/';
    $skipDirs = '#/vendor/(magento|composer|symfony|laminas|phpunit|monolog|psr|guzzlehttp|league|doctrine|webonyx|php-|sebastian|nikic|colinmollenhour|elasticsearch|opensearch|aws|google|tubalmartin|wikimedia)/|/Test/|/tests/|/dev/#';
    $usesMagento = []; $usesOwn = []; $ownLines = []; $libs = [];
    foreach (["$root/app/code", "$root/vendor"] as $base) {
        if (!is_dir($base)) continue;
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            $p = $f->getPathname();
            if (substr($p, -4) !== '.php' || preg_match($skipDirs, $p)) continue;
            $src = @file_get_contents($p); if ($src === false) continue;
            $rel = substr($p, strlen($root) + 1); $parts = explode('/', $rel);
            $need = $parts[0] === 'vendor' ? 3 : 4;
            if (count($parts) <= $need) continue;
            $mod = implode('/', array_slice($parts, 0, $need));
            // Only Magento modules own store data; crypto libraries (phpseclib, sodium_compat, jwt...) are implementations.
            $isModule = is_file("$root/$mod/registration.php") || is_file("$root/$mod/etc/module.xml");
            if (preg_match($magento, $src)) { if ($isModule) $usesMagento[$mod] = ($usesMagento[$mod] ?? 0) + 1; }
            if (preg_match_all($own, $src, $mm, PREG_OFFSET_CAPTURE)) {
                if (!$isModule) { $libs[$mod] = ($libs[$mod] ?? 0) + 1; continue; }
                $usesOwn[$mod] = ($usesOwn[$mod] ?? 0) + 1;
                foreach (array_slice($mm[0], 0, 2) as $hit) { $line = substr_count(substr($src, 0, $hit[1]), "\n") + 1; $ownLines[] = "$rel:$line: $hit[0]"; }
            }
        }
    }
    arsort($usesMagento); arsort($usesOwn);
    heading('EXTENSIONS AND ENCRYPTION');
    field('Magento root', $root);
    $files = fn(int $n) => sprintf('%4d file%s ', $n, $n === 1 ? ' ' : 's');
    section('Using Magento\'s encryptor - their data IS rotated by the key change');
    foreach ($usesMagento as $m => $n) say(sprintf('   %s %s', $files($n), $m));
    section('Using their OWN crypto - NOT rotated, invisible to any database scan');
    if (!$usesOwn) say('   ' . green('none found'));
    foreach ($usesOwn as $m => $n) say(sprintf('   %s %s', $files($n), red($m)));
    if ($usesOwn) {
        wrap('Each of these keeps its own key somewhere (its own config field, a file, or the same env.php read directly). Rotating the Magento key does nothing to their data, and re-encrypting will not touch it. Follow each extension\'s own procedure, and test that feature after the rotation.', '   ', '   ');
    }
    if ($ownLines) { say(''); say(dim('   WHERE')); foreach (array_slice($ownLines, 0, 40) as $l) say('     ' . dim($l)); }
    if ($libs) { arsort($libs); section('Crypto libraries present - implementations, not data owners'); foreach ($libs as $m => $n) say(sprintf('   %s %s', $files($n), dim($m))); }
    say('');
    return 0;
}

/* ---------- code-scan needs no bootstrap ---------- */
if ($command === 'code-scan') { exit(codeScan($root)); }

/* ---------- bootstrap Magento: its encryptor is the only crypto used ---------- */
// Bootstrapping Magento on a PHP newer than the release targets prints hundreds of deprecation
// notices from vendor code. They are not findings of this script and they bury the report, so
// deprecations are silenced and everything else PHP says goes to stderr, leaving stdout clean
// and pipeable. Re-applied after bootstrap because developer mode turns display_errors back on.
$quietPhp = function (): void { error_reporting(E_ALL & ~E_DEPRECATED); @ini_set('display_errors', 'stderr'); };
$quietPhp();
require "$root/app/bootstrap.php";
$bootstrap = \Magento\Framework\App\Bootstrap::create(BP, $_SERVER);
$om = $bootstrap->getObjectManager();
$quietPhp();
/** @var \Magento\Framework\Encryption\EncryptorInterface $encryptor */
$encryptor = $om->get(\Magento\Framework\Encryption\EncryptorInterface::class);
$env = include "$root/app/etc/env.php";
$keys = preg_split('/\s+/s', trim((string)$env['crypt']['key']));
$latestKey = count($keys) - 1;
$retiredIdx = []; $keyAdapters = []; $badKeyLines = [];
foreach ($keys as $i => $k) {
    if (strpos(trim($k), 'retired-') === 0) { $retiredIdx[$i] = true; continue; }
    $material = keyMaterial($k);
    if ($material === null) { $badKeyLines[$i] = true; continue; }
    try { $keyAdapters[$i] = new \Magento\Framework\Encryption\Adapter\SodiumChachaIetf($material); } catch (Throwable $e) { $badKeyLines[$i] = true; }
}
/* ---------- encrypt: produce one value, no database involved ---------- */
if ($command === 'encrypt') {
    $value = (string)$opt['value'];
    if ($opt['stdin'] === true || $value === '-') {
        // Preferred for real secrets: nothing lands in the shell history or in ps output.
        $value = rtrim((string)stream_get_contents(STDIN), "\n");
    }
    if ($value === '') {
        fwrite(STDERR, "encrypt needs --value=SECRET, or --stdin to read it from standard input\n");
        exit(2);
    }

    // Which key, and which line number to stamp on the front. They are separate choices: the number
    // is only a label saying where Magento should look, so a mismatch produces a value nothing reads.
    $line = $opt['key-line'] !== '' ? (int)$opt['key-line'] : $latestKey;
    if ($opt['key'] !== '') {
        $material = keyMaterial((string)$opt['key']);
        if ($material === null) {
            fwrite(STDERR, "--key must be a Magento key: 32 characters, or 'base64...' decoding to 32 bytes\n");
            exit(2);
        }
    } else {
        if (!isset($keys[$line])) {
            fwrite(STDERR, sprintf("env.php has no key line %d; it holds %d line(s), 0 to %d\n", $line, count($keys), count($keys) - 1));
            exit(2);
        }
        $material = keyMaterial($keys[$line]);
        if ($material === null) {
            fwrite(STDERR, sprintf("key line %d is retired or unusable; pass --key=KEY to encrypt with something else\n", $line));
            exit(2);
        }
    }

    heading('MAGENTO 2 ENCRYPTION KEY ROTATION - ENCRYPT');
    field('Magento root', $root);
    field('Key', sprintf('%s, fingerprint %s', $opt['key'] !== '' ? 'given with --key' : "key line $line from env.php", cyan(keyFingerprint($material))));
    field('Prefix', sprintf('%d:3 - Magento will look for the key on line %d', $line, $line));

    // Magento's own adapter, so the bytes are exactly what Magento writes.
    $adapter = new \Magento\Framework\Encryption\Adapter\SodiumChachaIetf($material);
    $cipher = $line . ':3:' . base64_encode($adapter->encrypt($value));

    section('RESULT');
    say('   ' . $cipher);

    // Say plainly whether this site can read what was just produced. A value encrypted with a key
    // that is not on the line it names looks fine and decrypts to nothing.
    say('');
    $back = '';
    try { $back = (string)$encryptor->decrypt($cipher); } catch (Throwable $e) { $back = ''; }
    if ($back === $value) {
        say('   ' . green('This Magento can read it back.') . ' Safe to store as-is.');
    } elseif ($back === '') {
        say('   ' . yellow('This Magento CANNOT read it back.') . sprintf(' Line %d does not hold the key it was encrypted with,', $line));
        say('   so Magento would decrypt this to nothing. Either stamp a different --key-line, or put that key on line ' . $line . '.');
    } else {
        // Magento trims what it decrypts, so a secret edged with whitespace or NUL comes back shorter.
        say('   ' . yellow('It reads back, but not byte-for-byte.') . ' Magento trims whitespace and NUL bytes from every');
        say('   decrypted value, so ' . (strlen($value) - strlen($back)) . ' byte(s) at the edges of this secret will not survive a round trip.');
    }
    say('');
    exit(0);
}

$db = $env['db']['connection']['default'];
$dsn = sprintf('mysql:host=%s;dbname=%s;charset=utf8mb4', $db['host'], $db['dbname']);
$unbuffered = defined('Pdo\\Mysql::ATTR_USE_BUFFERED_QUERY') ? \Pdo\Mysql::ATTR_USE_BUFFERED_QUERY : PDO::MYSQL_ATTR_USE_BUFFERED_QUERY;
try {
    // A short connect timeout: an unreachable host otherwise hangs for over a minute with nothing on screen.
    $reader = new PDO($dsn, $db['username'], $db['password'], [$unbuffered => false, PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 15]);
    $writer = new PDO($dsn, $db['username'], $db['password'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 15]);
} catch (PDOException $e) {
    fwrite(STDERR, sprintf(
        "cannot connect to the database %s on %s%s as user '%s'\n  %s\n\n" .
        "This is the db/connection/default block of %s/app/etc/env.php, read as-is.\n" .
        "Check the host, port, credentials and that the server accepts connections from here.\n",
        $db['dbname'] ?? '?', $db['host'] ?? '?', isset($db['port']) ? ':' . $db['port'] : '',
        $db['username'] ?? '?', $e->getMessage(), $root));
    exit(2);
}
$schema = $db['dbname'];

// Every mode except `re-encrypt --apply` runs in a READ-ONLY database session, enforced by the server:
// any write attempted on these connections is rejected by MySQL/MariaDB, not just avoided by this code.
$sessionMode = green('READ-ONLY, enforced by the server');
if (!($command === 're-encrypt' && $opt['apply'] === true)) {
    foreach ([$reader, $writer] as $conn) {
        try { $conn->exec('SET SESSION transaction_read_only = 1'); }
        catch (Throwable $e) { try { $conn->exec('SET SESSION tx_read_only = 1'); } catch (Throwable $e2) { $sessionMode = yellow('read-only could NOT be enforced on this server; this script still only reads'); } }
    }
} else {
    $sessionMode = red('WRITABLE - --apply was given, rows WILL be changed');
}

$oldKeyFallback = null;
if ($opt['old-key'] !== '') {
    $material = keyMaterial((string)$opt['old-key']);
    if ($material === null) { fwrite(STDERR, "--old-key must be a Magento key: 32 characters, or 'base64...' decoding to 32 bytes\n"); exit(2); }
    $oldKeyFallback = new \Magento\Framework\Encryption\Adapter\SodiumChachaIetf($material);
}

/* ---------- header ---------- */
heading('MAGENTO 2 ENCRYPTION KEY ROTATION - ' . strtoupper($command));
field('Magento root', $root);
field('Database', sprintf('%s @ %s', $schema, $db['host']));
field('DB session', $sessionMode);
field('PHP', sprintf('%s   sodium: %s   mcrypt: %s', PHP_VERSION,
    extension_loaded('sodium') || function_exists('sodium_crypto_aead_chacha20poly1305_ietf_decrypt') ? green('yes') : red('no'),
    mcryptAvailable() ? green(extension_loaded('mcrypt') ? 'yes (extension)' : 'yes (polyfill)') : yellow('no - values with prefix 0:0, 0:1 or 0:2 cannot be decrypted here')));
field('Memory limit', $memNow . ($memNow !== $memWas ? dim(" (raised from $memWas: the mcrypt polyfill needs the headroom)") : ''));
field('Keys', sprintf('%d line(s) in app/etc/env.php under crypt/key', count($keys)));
foreach ($keys as $i => $k) say(str_repeat(' ', 19) . keyLineDescription($i, $k, $latestKey));
if ($oldKeyFallback) say(str_repeat(' ', 19) . cyan('--old-key') . ' supplied, fp ' . cyan(keyFingerprint(keyMaterial((string)$opt['old-key']))) . dim(' - tried whenever env.php cannot decrypt a cipher-3 value'));
if ($badKeyLines) { say(''); say(' ' . red('WARNING') . ': key line(s) ' . implode(', ', array_keys($badKeyLines)) . ' are not valid keys. Fix env.php before trusting anything below.'); }

/* ---------- explain: one value, spelled out ---------- */
if ($command === 'explain') {
    $value = (string)$opt['value']; $explainCtx = [];
    if ($value === '' && $opt['table'] !== '' && $opt['column'] !== '') {
        $pk = primaryKey($writer, $schema, (string)$opt['table']);
        if (!$pk) { fwrite(STDERR, "table {$opt['table']} has no primary key; pass --value=... instead\n"); exit(2); }
        $st = $writer->prepare(sprintf('SELECT `%s` v FROM `%s` WHERE `%s`=? LIMIT 1', $opt['column'], $opt['table'], $pk[0]));
        $st->execute([$opt['id']]);
        $value = (string)($st->fetchColumn() ?: '');
        if ($value === '') { fwrite(STDERR, "no value in {$opt['table']}.{$opt['column']} where {$pk[0]}={$opt['id']}\n"); exit(2); }
        $w = $writer->prepare('SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME=? AND COLUMN_NAME=?');
        $w->execute([$schema, $opt['table'], $opt['column']]);
        $width = $w->fetchColumn();
        if ($width !== false && $width !== null && strlen($value) === (int)$width) $explainCtx['column_limit'] = (int)$width;
    }
    if ($value === '') { fwrite(STDERR, "explain needs --value='0:3:...' or --table=T --column=C --id=N\n"); exit(2); }

    section('THE VALUE');
    say('   ' . substr($value, 0, 92) . (strlen($value) > 92 ? dim('...') : '') . dim(sprintf('  (%d characters)', strlen($value))));
    $parsed = parseCipher($value);
    if ($parsed === null) {
        say('');
        say('   ' . yellow('This is not a whole Magento ciphertext.') . ' Magento values look like key:cipher:base64, e.g. 0:3:xxx');
        if (preg_match_all(EMBEDDED_RE, $value, $mm)) {
            say('   It does however CONTAIN ' . count($mm[0]) . ' encrypted value(s), on key line(s) ' . implode(', ', array_unique($mm[1])) . '.');
            say('   ' . dim('That is normal for JSON, serialized PHP and query strings; this script re-encrypts them in place.'));
            // Copied out of JSON, the slashes base64 produces arrive escaped as \/ and would not parse.
            $value = str_replace('\\/', '/', $mm[0][0]);
            $parsed = parseCipher($value);
            say('   Explaining the first one: ' . substr($value, 0, 60) . '...');
        } else {
            printCiphertextLegend($keys, $latestKey); say(''); exit(1);
        }
    }
    if ($parsed === null) {
        say('');
        say('   ' . yellow('That value does not parse as a Magento ciphertext.'));
        printCiphertextLegend($keys, $latestKey);
        say('');
        exit(1);
    }
    $raw = base64_decode($parsed['data'], true);
    section('STRUCTURE');
    foreach (prefixExplanation($parsed, $keys, $latestKey) as $line) say('   ' . $line);
    say('   ' . sprintf('payload = %d base64 characters -> %s bytes%s', strlen($parsed['data']),
        $raw === false ? '?' : strlen($raw),
        $raw !== false && $parsed['version'] === 3 ? sprintf(' = 12 nonce + 16 tag + %d encrypted', max(0, strlen($raw) - SODIUM_OVERHEAD)) : ''));
    if ($parsed['iv'] !== null) say('   ' . 'this is the four-part mcrypt form, so the third part is the initialisation vector and the fourth is the data');

    $res = attempt($value, false, $explainCtx);
    section('RESULT');
    if ($res['code'] === null) {
        say('   ' . green('Decrypts.') . sprintf(' Plaintext is %d characters of printable text%s.', strlen((string)$res['plain']), isset($res['x']['via']) ? ' (via --old-key, not a key in env.php)' : ''));
        if ($parsed['key'] === $latestKey) say('   ' . green('Already on the latest key') . ' - nothing to do for this value.');
        else say('   ' . yellow(sprintf('On key line %d, not the latest (key%d)', $parsed['key'], $latestKey)) . ' - re-encrypt will move it.');
        say('   ' . ($opt['reveal'] === true ? 'PLAINTEXT: ' . $res['plain'] : dim('Plaintext hidden. Pass --reveal to print it (it is a secret; mind your shell history and screen).')));
        say('');
    } else {
        recordProblem($res['code'], $res['x'], (string)($opt['table'] ?: 'given'), (string)($opt['column'] ?: 'value'), (string)($opt['id'] !== '' ? 'id=' . $opt['id'] : ''), $value);
        say('   ' . red('Does not decrypt.') . ' The diagnosis and the fix are below.');
        printProblemReport($keys, $latestKey, true, '', true);
        say('');
        exit(1);
    }
    printCiphertextLegend($keys, $latestKey);
    say('');
    exit(0);
}

/* ---------- scan / verify / re-encrypt share one walk ---------- */
$only = array_filter(array_map('trim', explode(',', (string)$opt['tables'])));
$skip = array_filter(array_map('trim', explode(',', (string)$opt['exclude'])));
$cols = columns($writer, $schema, $only, $skip, (int)$opt['max-rows']);
$apply = $command === 're-encrypt' && $opt['apply'] === true;
$allowBinary = $opt['allow-binary'] === true;
$showAll = $opt['show-all'] === true;
$dumpFh = $backFh = $unreadFh = $unreadBackFh = null;
if ($command === 're-encrypt' && $opt['dump'] !== '') {
    $dumpFh = fopen((string)$opt['dump'], 'a'); $backFh = fopen($opt['dump'] . '.backup.sql', 'a');
    fwrite($dumpFh, "-- re-encrypt to key$latestKey, generated " . date('c') . "\n"); fwrite($backFh, "-- REVERSE of {$opt['dump']}: restores the old ciphertext\n");
}
$limit = (int)$opt['limit'];
/** Values that can never be read again are the only ones offered for clearing, with the reason kept as a comment. */
$offerToClear = function (string $code, string $t, string $col, array $row, array $pk, string $v) use (&$unreadFh, &$unreadBackFh, &$dumpFh, $opt, $writer): void {
    if (!$dumpFh) return;
    if (!$unreadFh) {
        $unreadFh = fopen($opt['dump'] . '.unreadable.sql', 'a'); $unreadBackFh = fopen($opt['dump'] . '.unreadable.backup.sql', 'a');
        fwrite($unreadFh, "-- Values that can no longer be decrypted by any key present. REVIEW, then run to clear them so verify can pass.\n");
        fwrite($unreadBackFh, "-- Reverse: restores the original (unreadable) ciphertext.\n");
    }
    $pkWhere = $pk ? implode(' AND ', array_map(fn($x) => "`$x`=" . $writer->quote((string)$row[$x]), $pk)) . ' AND ' : '';
    fwrite($unreadFh, sprintf("-- %s\nUPDATE `%s` SET `%s`=NULL WHERE %s`%s`=%s LIMIT 1;\n", $code, $t, $col, $pkWhere, $col, $writer->quote($v)));
    fwrite($unreadBackFh, sprintf("UPDATE `%s` SET `%s`=%s WHERE %s`%s` IS NULL LIMIT 1;\n", $t, $col, $writer->quote($v), $pkWhere, $col));
};
$totals = ['whole' => 0, 'embedded_values' => 0, 'on_old_key' => 0, 'updated' => 0, 'failed' => 0, 'legacy_cipher' => 0,
           'skipped_tables' => 0, 'old_recoverable' => 0, 'old_binary' => 0, 'old_unknown' => 0, 'old_dead' => 0, 'malformed' => 0, 'nested' => 0];
$noPk = []; $currentTable = null; $pk = [];

section($command === 're-encrypt' ? ($apply ? 'RE-ENCRYPTING (writing)' : 'RE-ENCRYPT DRY RUN (nothing is written)') : 'ENCRYPTED VALUES BY TABLE AND COLUMN');
printf(" %-40s %-26s %7s  %s\n", 'TABLE', 'COLUMN', 'VALUES', 'BREAKDOWN  ' . dim('(ciphertexts per keyLine:cipherVersion)'));
foreach ($cols as $c) {
    $t = $c['t']; $col = $c['c'];
    if ($c['skipped']) { printf(" %-40s %-26s %7s  %s\n", $t, $col, '-', yellow(sprintf('SKIPPED, ~%s rows is over --max-rows', $c['r']))); $totals['skipped_tables']++; continue; }
    if ($t !== $currentTable) { $currentTable = $t; $pk = primaryKey($writer, $schema, $t); }
    $selectCols = $pk ? array_merge($pk, [$col]) : [$col];
    // MySQL 8 refuses REGEXP on binary-charset columns (error 3995); LIKE works on bytes, so binary types get a LIKE-only prefilter.
    $isBinary = in_array($c['d'], ['blob','tinyblob','mediumblob','longblob','varbinary','binary'], true);
    $prefilter = $isBinary ? sprintf("(`%1\$s` LIKE '_:_:%%' OR `%1\$s` LIKE '__:_:%%' OR `%1\$s` LIKE '%%:3:%%')", $col) : sprintf(SQL_PREFILTER, $col);
    $sql = sprintf("SELECT %s FROM `%s` WHERE `%s` IS NOT NULL AND %s", '`' . implode('`,`', array_unique($selectCols)) . '`', $t, $col, $prefilter);
    try { $rs = $reader->query($sql); } catch (Throwable $e) { printf(" %-40s %-26s %7s  %s\n", $t, $col, '-', red('ERROR ') . substr($e->getMessage(), 0, 70)); continue; }
    $counts = []; $embedded = 0; $oldHere = 0; $updatedHere = 0; $failedHere = 0; $hits = 0; $deadHere = 0; $binaryHere = 0; $mangledHere = 0; $blockedHere = 0; $nestedHere = 0;
    while (($row = $rs->fetch(PDO::FETCH_ASSOC)) !== false) {
        $v = (string)$row[$col];
        $isWhole = (bool)preg_match(WHOLE_RE, $v, $wm);
        $isEmbedded = !$isWhole && (bool)preg_match(EMBEDDED_RE, $v);
        // Starts with a prefix but will not parse: mangled, not absent. Report it rather than skip it.
        $isMangled = !$isWhole && !$isEmbedded && (bool)preg_match('/^\d{1,2}:[0-3]:.{16,}$/s', $v);
        if (!$isWhole && !$isEmbedded && !$isMangled) continue;
        $hits++;
        $where = rowWhere($row, $pk);
        // A ciphertext exactly as long as the column can hold was almost certainly cut off on write.
        $ctx = ($c['len'] !== null && strlen($v) === (int)$c['len']) ? ['column_limit' => (int)$c['len']] : [];
        if ($isMangled) {
            [$code, $x] = classifyMangled($v);
            recordProblem($code, $x + $ctx, $t, $col, $where, $v);
            $mangledHere++; $totals['malformed']++;
            if ($command === 're-encrypt') $offerToClear($code, $t, $col, $row, $pk, $v);
            continue;
        }
        if ($isWhole) {
            $kv = (int)$wm[1]; $cv = (int)$wm[2];
            $counts["key$kv:$cv"] = ($counts["key$kv:$cv"] ?? 0) + 1;
            if ($cv !== 3) $totals['legacy_cipher']++;
            $nested = nestedOnOldKey($v, $latestKey);
            if ($kv === $latestKey && $cv === 3 && !$nested) continue;
            if ($nested) { $totals['nested'] += count($nested); $nestedHere += count($nested); }
            $oldHere++;
            if ($limit && $command === 're-encrypt' && $totals['updated'] >= $limit) continue;
            $res = attempt($v, $command === 're-encrypt' ? $allowBinary : false, $ctx);
            $emptySecret = $res['code'] === 'EMPTY_PLAINTEXT';   // decrypted fine; the secret itself is empty
            if ($res['code'] !== null) {
                recordProblem($res['code'], $res['x'], $t, $col, $where, $v);
                if (!$emptySecret) {
                    if (isDead($res['code'])) { $totals['old_dead']++; $deadHere++; }
                    elseif ($res['code'] === 'BINARY_PLAINTEXT') { $totals['old_binary']++; $binaryHere++; }
                    else { $totals['old_unknown']++; $blockedHere++; }
                    if ($command === 're-encrypt') {
                        $failedHere++;
                        if (isClearable($res['code'])) $offerToClear($res['code'], $t, $col, $row, $pk, $v);
                    }
                    continue;
                }
            }
            $totals['old_recoverable']++;
            if ($command !== 're-encrypt') continue;
            $plainOut = (string)$res['plain'];
            if ($nested) {
                [$plainOut, $nRep, $nFail] = reencryptEmbedded($plainOut, $latestKey, $allowBinary, ['t' => $t, 'c' => $col . ' (nested)', 'w' => $where]);
                if ($nFail) {
                    say('   ' . yellow('SKIPPED') . " $t.$col $where: " . $nFail . ' nested value(s) would not decrypt, so the row is left alone');
                    $failedHere += $nFail; $blockedHere++; $totals['old_unknown']++;
                    continue;
                }
            }
            $newValue = $encryptor->encrypt($plainOut);
        } else {
            $embedded++; $totals['embedded_values']++;
            if (!preg_match_all(EMBEDDED_RE, $v, $all)) continue;
            foreach ($all[1] as $ek) $counts['key' . (int)$ek . ':3'] = ($counts['key' . (int)$ek . ':3'] ?? 0) + 1;
            $old = array_filter($all[1], fn($k) => (int)$k !== $latestKey);
            if (!$old) continue;
            $oldHere++;
            if ($limit && $command === 're-encrypt' && $totals['updated'] >= $limit) continue;
            [$newValue, $rep, $fail] = reencryptEmbedded($v, $latestKey, $command === 're-encrypt' ? $allowBinary : false, ['t' => $t, 'c' => $col, 'w' => $where]);
            if ($fail) {
                if ($command === 're-encrypt') $failedHere += $fail;
                if ($rep === 0) { $totals['old_unknown']++; $blockedHere++; } else { $totals['old_recoverable']++; }
                if ($command === 're-encrypt') { say('   ' . yellow('SKIPPED') . " $t.$col $where: " . $fail . ' embedded value(s) would not decrypt, so the row is left alone'); continue; }
                continue;
            }
            $totals['old_recoverable']++;
            if ($command !== 're-encrypt') continue;
            if ($rep === 0) continue;
        }
        // build the UPDATE: by primary key when present, else by the exact old value (unique: random nonce)
        // Compare-and-swap: the old value is always part of WHERE, so a row the live site rewrote between our
        // read and write is left alone (affected rows = 0) instead of being overwritten with stale data.
        $byPk = $pk ? implode(' AND ', array_map(fn($p) => "`$p`=" . $writer->quote((string)$row[$p]), $pk)) . ' AND ' : '';
        if (!$pk && !isset($noPk[$t])) $noPk[$t] = true;
        $upd = sprintf("UPDATE `%s` SET `%s`=%s WHERE %s`%s`=%s LIMIT 1;", $t, $col, $writer->quote($newValue), $byPk, $col, $writer->quote($v));
        $rev = sprintf("UPDATE `%s` SET `%s`=%s WHERE %s`%s`=%s LIMIT 1;", $t, $col, $writer->quote($v), $byPk, $col, $writer->quote($newValue));
        if ($dumpFh) { fwrite($dumpFh, "$upd\n"); fwrite($backFh, "$rev\n"); }
        if ($apply) { if ($writer->exec($upd) !== 1) { say('   ' . yellow('SKIPPED') . " $t.$col $where: the row changed underneath us, re-run to catch it"); $totals['failed']++; continue; } }
        $updatedHere++; $totals['updated']++;
    }
    $rs->closeCursor();
    if ($hits === 0) continue;
    $totals['whole'] += $hits - $embedded - $mangledHere; $totals['on_old_key'] += $oldHere; $totals['failed'] += $failedHere;
    $notes = [];
    foreach ($counts as $k => $n) $notes[] = "$k=$n";
    if ($embedded) $notes[] = "embedded=$embedded";
    if ($nestedHere) $notes[] = yellow("nested=$nestedHere");
    if ($oldHere) $notes[] = yellow("ON-OLD-KEY=$oldHere");
    if ($binaryHere) $notes[] = yellow("binary=$binaryHere");
    if ($blockedHere) $notes[] = red("cannot-decrypt=$blockedHere");
    if ($mangledHere) $notes[] = red("MALFORMED=$mangledHere");
    if ($deadHere) $notes[] = dim("unreadable=$deadHere");
    if ($command === 're-encrypt' && $oldHere) $notes[] = ($apply ? green('updated=' . $updatedHere) : 'would_update=' . $updatedHere);
    if ($failedHere) $notes[] = red("FAILED=$failedHere");
    if (!$pk) $notes[] = dim('no-PK, matched by value');
    printf(" %-40s %-26s %7d  %s\n", $t, $col, $hits, implode('  ', $notes));
}
if ($dumpFh) { fclose($dumpFh); fclose($backFh); }
if ($unreadFh) { fclose($unreadFh); fclose($unreadBackFh); }

/* ---------- summary ---------- */
$blocking = $totals['old_recoverable'] + $totals['old_binary'] + $totals['old_unknown'];
section('SUMMARY');
field('Encrypted values', sprintf('%s whole value(s), %s value(s) with ciphertext embedded in JSON, serialized PHP or query strings',
    number_format($totals['whole']), number_format($totals['embedded_values'])));
field('On an older key', number_format($totals['on_old_key']) . ($totals['on_old_key'] ? ':' : ' - nothing to rotate'));
if ($totals['on_old_key']) {
    if ($totals['old_recoverable']) say(sprintf('   %s  %s', green(str_pad(number_format($totals['old_recoverable']), 8, ' ', STR_PAD_LEFT)), $command === 're-encrypt' && $apply ? 'decrypted and moved to the latest key' : 'decrypt cleanly and are ready to be re-encrypted'));
    if ($totals['old_binary'])      say(sprintf('   %s  %s', yellow(str_pad(number_format($totals['old_binary']), 8, ' ', STR_PAD_LEFT)), 'decrypt correctly but hold binary data - they need --allow-binary, and they block retiring keys until they move'));
    if ($totals['old_unknown'])     say(sprintf('   %s  %s', red(str_pad(number_format($totals['old_unknown']), 8, ' ', STR_PAD_LEFT)), 'cannot be decrypted with what is available here - these block retiring keys, see the diagnosis below'));
    if ($totals['old_dead'])        say(sprintf('   %s  %s', dim(str_pad(number_format($totals['old_dead']), 8, ' ', STR_PAD_LEFT)), 'are permanently unreadable dead data - nothing readable is lost, they do not block retiring keys'));
}
if ($totals['nested']) field('Nested', yellow(number_format($totals['nested']) . ' ciphertext(s)') . ' found INSIDE the plaintext of another value, on an older key. Magento stores admin 2FA secrets this way. No database scan can see these, so they are the ones that lock people out after a key is retired.');
if ($totals['malformed']) field('Malformed', red(number_format($totals['malformed']) . ' value(s)') . ' start like a ciphertext but do not parse - mangled in storage, see the diagnosis below');
if ($totals['legacy_cipher']) field('Legacy mcrypt', sprintf('%s value(s) with prefix 0:0, 0:1 or 0:2 - encrypted before Magento 2.1%s',
    number_format($totals['legacy_cipher']), mcryptAvailable() ? '' : ', and this PHP has no mcrypt'));
if ($totals['skipped_tables']) field('Tables skipped', yellow(number_format($totals['skipped_tables']) . ' column(s) skipped by --max-rows - the report below is incomplete'));
if ($noPk) field('No primary key', implode(', ', array_keys($noPk)) . dim(' - rows matched by their exact old value, which is unique because every ciphertext carries a random nonce'));
if ($retiredIdx) field('Retired keys', 'line(s) ' . implode(', ', array_keys($retiredIdx)) . dim(' - overwritten on purpose, they decrypt nothing'));
if ($command === 're-encrypt') {
    field($apply ? 'Written' : 'Dry run', sprintf('%s %s row(s)%s', $apply ? 'updated' : 'would update', number_format($totals['updated']),
        $opt['dump'] !== '' ? '; statements in ' . $opt['dump'] . ' (reverse in ' . $opt['dump'] . '.backup.sql)' : ''));
}

printProblemReport($keys, $latestKey, $showAll, (string)$opt['dump']);

/* ---------- what to do next ---------- */
section('NEXT STEPS');
if ($command === 'scan') {
    if ($totals['on_old_key'] === 0) {
        if (count($keys) - count($retiredIdx) <= 1) {
            wrap('Nothing depends on an older key and every older key line is already retired. The rotation is complete; keep the retired lines in place for good.', '   ', '   ');
        } else {
            wrap('Everything is already on key' . $latestKey . '. Run: php ' . basename(__FILE__) . ' verify   and if it exits 0, retire the older keys with retire-keys --apply.', '   ', '   ');
        }
    } else {
        $step = 1;
        if ($totals['old_unknown']) wrap('Deal with the values that cannot be decrypted first (above). Re-encrypting around them is fine, but retiring keys is not, until you have decided what happens to them.', '       ', '   ' . ($step++) . '.  ');
        wrap('Rehearse on a copy: php ' . basename(__FILE__) . ' re-encrypt --dump=rotation.sql   then read rotation.sql before anything is written.', '       ', '   ' . ($step++) . '.  ');
        wrap('Apply: php ' . basename(__FILE__) . ' re-encrypt --apply' . ($totals['old_binary'] ? ' --allow-binary' : '') . '   then bin/magento cache:flush.', '       ', '   ' . ($step++) . '.  ');
        wrap('Confirm with verify (it must exit 0), and only then retire-keys --apply.', '       ', '   ' . ($step++) . '.  ');
        wrap('Check what code-scan reports: extensions with their own crypto are not covered by any of this.', '       ', '   ' . ($step++) . '.  ');
    }
    say('');
    wrap('To understand one value: php ' . basename(__FILE__) . " explain --value='0:3:...' (or explain --table=T --column=C --id=N)", '       ', '   ' . dim('tip') . '  ');
    say('');
}
if ($command === 're-encrypt') {
    if (!$apply) {
        wrap('Nothing was written. Review ' . ($opt['dump'] !== '' ? $opt['dump'] : 'the output above, and re-run with --dump=FILE to get the exact SQL') . ', then re-run with --apply.', '       ', '   ' . dim('->') . '  ');
    } else {
        wrap('Run bin/magento cache:flush, then verify (it must exit 0), then retire-keys --apply.', '       ', '   ' . dim('->') . '  ');
        wrap('Test what actually uses these secrets before retiring anything: payments, shipping and ERP integrations, outgoing mail, admin 2FA.', '       ', '   ' . dim('->') . '  ');
    }
    if ($totals['old_binary'] && !$allowBinary) wrap($totals['old_binary'] . ' value(s) were left behind because their plaintext is binary. Cipher 3 verified the key on those, so re-running with --allow-binary is safe.', '       ', '   ' . dim('->') . '  ');
    if ($totals['old_unknown']) wrap($totals['old_unknown'] . ' value(s) could not be decrypted and were NOT touched. Read the diagnosis above; if an old key is simply missing, re-run with --old-key=<that key>.', '       ', '   ' . dim('->') . '  ');
    say('');
}
$clean = $blocking === 0 && $totals['skipped_tables'] === 0;
if ($command === 'verify') {
    if ($clean) {
        say('   ' . green('VERIFY: PASS') . ' - nothing readable depends on an older key.' . ($totals['old_dead'] ? ' ' . $totals['old_dead'] . ' already-unreadable value(s) remain; clearing them is optional.' : ''));
        wrap('Next: retire-keys --apply. Never delete a key line from env.php - the first number in every ciphertext is the line position, so removing a line renumbers the rest and takes the site down.', '       ', '   ' . dim('->') . '  ');
        say('');
        exit(0);
    }
    say('   ' . red('VERIFY: FAIL') . ' - ' . $blocking . ' value(s) still depend on an older key' . ($totals['skipped_tables'] ? ' and ' . $totals['skipped_tables'] . ' column(s) were skipped by --max-rows' : '') . '.');
    wrap('Do NOT retire or delete any key yet. Run re-encrypt' . ($totals['old_binary'] ? ' --allow-binary' : '') . ' first, and work through the diagnosis above for anything that will not decrypt.', '       ', '   ' . dim('->') . '  ');
    say('');
    exit(1);
}
if ($command === 'retire-keys') {
    if (!$clean) {
        say('   ' . red('RETIRE-KEYS: REFUSED') . ' - ' . $blocking . ' value(s) still depend on an older key.');
        wrap('Run re-encrypt, then verify. Retiring a key those values need would make them unreadable for good.', '       ', '   ' . dim('->') . '  ');
        say('');
        exit(1);
    }
    if ($totals['old_dead']) say('   ' . dim($totals['old_dead'] . ' already-unreadable value(s) stay on the retired keys as dead ciphertext; nothing readable is lost.'));
    if (count($keys) < 2) { say('   Nothing to do: env.php holds a single key.'); say(''); exit(0); }
    $envFile = "$root/app/etc/env.php";
    $newKeys = $keys;
    foreach ($newKeys as $i => $k) { if ($i !== $latestKey && strpos($k, 'retired-') !== 0) $newKeys[$i] = 'retired-' . bin2hex(random_bytes(12)); }  // 32 chars; recognisable; decrypts nothing
    foreach ($keys as $i => $k) {
        say(sprintf('   key%-2d %s...  ->  %s', $i, substr($k, 0, 8),
            $i === $latestKey ? green('KEPT, active, line position unchanged') : (strpos($k, 'retired-') === 0 ? dim('already retired') : yellow("overwritten with 'retired-<random>', line kept"))));
    }
    if ($opt['apply'] !== true) { say(''); say('   ' . dim('DRY RUN: env.php not changed. Re-run with --apply.')); say(''); exit(0); }
    $backup = $envFile . '.bak-' . date('Ymd-His');
    if (!copy($envFile, $backup)) { say('   ' . red('Could not back up env.php; aborting.')); exit(1); }
    chmod($backup, 0600);
    $envData = include $envFile;
    $envData['crypt']['key'] = implode("\n", $newKeys);
    if (file_put_contents($envFile, "<?php\nreturn " . var_export($envData, true) . ";\n") === false) { say('   ' . red('Write failed') . "; env.php unchanged, backup at $backup"); exit(1); }
    say('');
    say('   ' . green('RETIRE-KEYS: DONE') . ' - older keys overwritten, ' . count($newKeys) . ' line(s) kept. Backup: ' . $backup);
    wrap('Run bin/magento cache:flush, then verify again (it must still PASS).', '       ', '   ' . dim('->') . '  ');
    say('');
    exit(0);
}
exit($totals['failed'] ? 1 : 0);
