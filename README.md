# Magento 2 Encryption Key Rotation Tool

One standalone PHP script that does the whole encryption-key rotation for a Magento 2 / Adobe Commerce
store: finds every encrypted value in the database, including the ones hidden inside JSON, serialized
PHP and other encrypted values, moves them all onto the new key, proves that nothing still depends on
the old key, and retires the old key safely.

It exists because Adobe's own commands do not do this. `bin/magento encryption:key:change` appends a
key and re-encrypts nothing. `bin/magento encryption:data:re-encrypt` (2.4.8 and the February 2025
patches) re-encrypts two tables, `core_config_data` and the card-number column of
`sales_order_payment`, and only those. OAuth tokens, integration secrets, password-reset tokens,
admin 2FA secrets and every table created by a payment, shipping or ERP extension stay on the old key.

The first version of this tool was written for CosmicSting (CVE-2024-34102) in 2024. This version was
rebuilt for StyleSmuggler (CVE-2026-75650) in September 2026, after which Adobe once again told every
merchant to rotate the encryption key and every credential it protected. Background:

- [Magento 2 Encryption Key Rotation: How we worked around core deficiencies with a flexible script](https://www.linkedin.com/pulse/magento-2-encryption-key-rotation-how-we-worked-around-core-deficiencies-inqzc/) (2024)
- The September 2026 follow-up article, covering StyleSmuggler, what Adobe changed, and this script.

## Disclaimer

This tool is provided as-is, without any warranty. Use at your own risk. Rehearse on a copy of the
database first, take a backup before writing anything, and test payments, integrations, mail and
admin login after the rotation.

## What it does

- **Uses Magento's own encryptor.** It bootstraps Magento and every decrypt and encrypt goes through
  `Magento\Framework\Encryption\EncryptorInterface`. No cryptography is re-implemented. Legacy
  32-character keys and the `base64...` keys introduced in 2.4.7 are both handled, on any line, in
  any mix.
- **Scans every text and binary column of every table** for ciphertext, whole values and values
  embedded inside JSON, serialized PHP and query strings. Reports counts per key line and cipher
  version.
- **Finds nested ciphertext**: an encrypted value whose plaintext contains another encrypted value.
  Magento's two-factor module stores admin TOTP secrets this way, and a plain database scan cannot
  see the inner one. Rotating only the outer one locks every admin out once the old key is retired.
- **Diagnoses every value that will not decrypt** and says what to do about it: key missing from
  `env.php`, key lines reordered, ciphertext truncated by a narrow column, base64 mangled by a bad
  import, legacy mcrypt without the extension, and so on. Each problem is attributed to the exact
  table, column and row. The full list is under *Diagnosis codes* below.
- **Read-only unless told otherwise.** Every command except `re-encrypt --apply` runs its database
  session with `transaction_read_only = 1`, enforced by the server. `retire-keys` writes only
  `env.php`.
- **Dry run by default.** `re-encrypt` writes nothing without `--apply`. With `--dump=FILE` it
  produces the exact `UPDATE` statements for review, plus a reverse file that undoes them.
- **Never deletes a key line.** The number at the front of every ciphertext is the line position of
  the key in `crypt/key`; delete a line and every later value becomes unreadable. `retire-keys`
  overwrites old keys in place with a `retired-...` placeholder, keeping the count and order of
  lines, and refuses to run until `verify` passes.
- **Scans the code, not only the database.** `code-scan` lists the extensions that use Magento's
  encryptor (rotated by this tool) and the ones that roll their own crypto (not rotated by anything;
  follow that extension's own procedure).

## Requirements

- A Magento 2.4.x install that can bootstrap from the command line. The script is run from the
  Magento root (or given `--magento-root=PATH`) with the same PHP binary and OS user as
  `bin/magento`.
- PHP with the `sodium` extension (standard for Magento 2.4). Values from before Magento 2.1 use
  mcrypt; the script decrypts them if the `mcrypt` extension or the `phpseclib/mcrypt_compat`
  polyfill Magento ships with is present.
- MySQL or MariaDB. The read-only session guard uses `SET SESSION transaction_read_only`, which
  every supported version has.

## Installation

1. Download `magento-key-rotation.php`.
2. Put it in the root directory of the Magento installation, next to `bin/magento`.
3. Run `php magento-key-rotation.php help`, then `php magento-key-rotation.php scan`.

## Keys: how Magento stores them and how this tool treats them

Everything below follows from three facts about `crypt/key` in `app/etc/env.php`.

**One key per line.** The setting is a single string; multiple keys are separated by newlines, not
stored as an array. Adobe's `encryption:key:change` appends a line, and so does this tool's
guidance. A typical store after one rotation:

```
'crypt' => [
    'key' => 'a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5
base64Vp3aZ9k1Q8sT2wXyL4mN6oP7rS0uV1wX3yZ5aB7cD9e='
],
```

**The number at the front of a ciphertext is a line position.** A value that reads `1:3:...` was
encrypted with the key on line 1, counting from 0. It is not an identifier. Remove line 0 and the
key on line 1 becomes line 0, so every `1:3:...` value now points at a line that does not exist and
every `0:3:...` value points at the wrong key. That is why this tool retires a key by overwriting it
in place and never by deleting the line, and why the `scan` report identifies keys by line number.

**Two key formats exist.** A legacy key is 32 characters, the hex output of `md5()`. Since Magento
2.4.7 a generated key is the word `base64` followed by 44 base64 characters, which decode to 32
random bytes. Magento's encryptor decodes a key that starts with `base64` and uses any other key as
it is. Both formats can sit on different lines of the same store, which is what happens to any
store installed before 2.4.7 and rotated after. The 2.4.4, 2.4.5 and 2.4.6 patch lines still
generate the legacy format.

This tool accepts either format anywhere a key is given: on any line of `env.php`, in `--old-key`,
and in `encrypt --key`. Keys are never printed. Every report shows a fingerprint instead, the first
eight hex characters of the SHA-256 of the key bytes, so you can compare `env.php` files between
environments without exposing anything:

```
 Keys              2 line(s) in app/etc/env.php under crypt/key
                   key0  legacy 32-char   fp e88316b6  older key
                   key1  base64 (2.4.7+)  fp f9344e81  <- LATEST: everything is re-encrypted to this key
```

A retired line looks like `retired-3f9a...` and is reported as such. A line that does not decode to
32 bytes is reported as unusable, with the values that depend on it listed under
`KEY_LINE_UNUSABLE`.

To generate a key by hand, use Adobe's own recipe: `openssl rand -base64 32` with `base64`
prepended for 2.4.7 and later, `openssl rand -hex 16` for earlier lines. Append it as a new line;
do not replace the old one.

## Commands and options

Every command takes `--magento-root=PATH` (default: the directory the script is in) and
`--no-color`. Options are written `--name=value`; flags are written `--name`.

### scan

```
php magento-key-rotation.php scan [--tables=a,b] [--exclude=a,b] [--max-rows=N] [--old-key=KEY] [--show-all]
```

Inventories every encrypted value in the database and diagnoses every one that will not decrypt.
Read-only. Exit code is always 0; the report is the result.

| Option | Effect |
|---|---|
| `--tables=a,b` | Look only at these tables. |
| `--exclude=a,b` | Skip these tables. Useful for a known false positive, such as a column of ordinary data that happens to start with digits and colons. |
| `--max-rows=N` | Skip tables whose estimated row count is above N. Skipped tables are listed in the report, which is then not a full inventory. |
| `--old-key=KEY` | Also try this key on any cipher-3 value that no key in `env.php` can decrypt. For a key that was removed from `env.php` or belongs to another environment. |
| `--show-all` | List every affected row under each diagnosis, instead of the first few. |

### explain (this is also how you decrypt a value)

```
php magento-key-rotation.php explain --value='0:3:...' [--reveal] [--old-key=KEY]
php magento-key-rotation.php explain --table=T --column=C --id=N [--reveal] [--old-key=KEY]
```

Takes one ciphertext and spells out its structure: which key line it names, which cipher version,
how many bytes of payload, whether it decrypts and, if not, which diagnosis applies and what to do.

| Option | Effect |
|---|---|
| `--value='0:3:...'` | The ciphertext itself. Quote it; base64 contains `/` and `=`. A value copied out of JSON with escaped slashes (`\/`) is accepted. |
| `--table=T --column=C --id=N` | Read the value from that row instead. The table needs a single-column primary key. |
| `--reveal` | Print the decrypted plaintext. Hidden by default because it is a secret; mind your shell history and your screen. |
| `--old-key=KEY` | Try this key if none in `env.php` works. |

To decrypt one configuration value:

```
php magento-key-rotation.php explain --table=core_config_data --column=value --id=42 --reveal
```

Exit code 0 if the value decrypts, 1 if it does not or is not a Magento ciphertext at all. If the
value is not a whole ciphertext but contains one, for example a JSON blob, the first embedded
ciphertext is explained.

### encrypt

```
php magento-key-rotation.php encrypt --value=SECRET [--key=KEY] [--key-line=N]
printf '%s' 'SECRET' | php magento-key-rotation.php encrypt --stdin [--key=KEY] [--key-line=N]
```

Produces one encrypted value for pasting into a row by hand, using Magento's own adapter so the
bytes are exactly what Magento would write. By default it uses the latest key line in `env.php`.

| Option | Effect |
|---|---|
| `--value=SECRET` | The plaintext. |
| `--stdin` (or `--value=-`) | Read the plaintext from standard input instead. Prefer this for real secrets: nothing lands in the shell history or in `ps` output. A trailing newline is stripped. |
| `--key=KEY` | Encrypt with this key instead of one from `env.php`. Either key format. |
| `--key-line=N` | Stamp this line number on the value instead of the latest. |

The result is decrypted again through Magento before it is printed, and the report says one of
three things: this site can read it back; this site cannot read it back, because line N does not
hold the key it was encrypted with; or it reads back but not byte-for-byte, because Magento trims
whitespace and NUL bytes from every decrypted value. A key line that is retired, unusable or does
not exist is refused with exit code 2.

### code-scan

```
php magento-key-rotation.php code-scan
```

Walks `app/code` and `vendor`, skips Magento's own modules and known libraries, and sorts every
module into two lists: the ones that call Magento's encryptor, whose data a rotation covers, and the
ones that call `openssl_encrypt`, `sodium_crypto_secretbox`, phpseclib, Defuse or mcrypt directly,
whose data it does not. For the second list it prints the file and line of each call. Needs no
database and no Magento bootstrap. Takes only `--magento-root`.

### re-encrypt

```
php magento-key-rotation.php re-encrypt [--dump=FILE] [--limit=N] [--allow-binary] [--old-key=KEY] [--tables=..] [--exclude=..] [--max-rows=N]
php magento-key-rotation.php re-encrypt --apply [--dump=FILE | --backup=FILE] [--limit=N] [--allow-binary] [--old-key=KEY] [...]
php magento-key-rotation.php re-encrypt --apply --from-dump=FILE
```

Decrypts every value that names an older key line and encrypts it again with the latest one,
including values embedded in JSON, serialized PHP and query strings, and values nested inside the
plaintext of another value. Without `--apply` it is a dry run and the database session is
read-only. The scan options (`--tables`, `--exclude`, `--max-rows`, `--old-key`, `--show-all`)
apply here as well.

| Option | Effect |
|---|---|
| `--apply` | Write. Without it nothing in the database changes. |
| `--dump=FILE` | Write one `UPDATE` per row to FILE and its reverse to `FILE.backup.sql`. Rows that can never be read again are written to `FILE.unreadable.sql` (statements that clear them) and `FILE.unreadable.backup.sql`. Files are opened in append mode, so use a fresh name per run. |
| `--from-dump=FILE` | With `--apply`: execute the reviewed statements in FILE exactly as written, instead of encrypting afresh. The file is checked first and only statements of the shape this tool writes are accepted. Rows that no longer match are reported as skipped. Cannot be combined with `--dump`. |
| `--backup=FILE` | With `--apply` and without `--dump`: where to write the reverse statements. Default `var/re-encrypt-<time>.backup.sql` under the Magento root, or the root itself if `var/` is not writable. Every `--apply` writes a backup. |
| `--limit=N` | Stop after N rows, for a staged rollout. Re-run to continue; rows already moved are skipped. |
| `--allow-binary` | Also re-encrypt values whose plaintext is not printable text. Safe for cipher 3, where the authentication tag has already proven the key was right. Never applied to mcrypt values, where garbage usually means the wrong key. |

Every `UPDATE` matches the row by primary key and by its current ciphertext, so a row the live site
changed in between affects nothing and is reported as skipped instead of being overwritten. Rows in
tables without a primary key are matched by their exact old value, which is unique because every
ciphertext carries a random nonce.

Exit code 0 when every value that needed moving was moved, 1 when any row was skipped or could
not be decrypted, 2 when the run could not start.

### verify

```
php magento-key-rotation.php verify [--old-key=KEY] [--tables=..] [--exclude=..] [--max-rows=N]
```

Exits 0 only when nothing readable in the database still depends on an older key. Values that are
permanently unreadable (truncated, mangled, or on a retired line) do not block it, since nothing
readable is lost by retiring the key. Binary plaintext that has not been moved does block it, as do
tables skipped by `--max-rows`. Exit 1 otherwise, with the rows and reasons listed.

### retire-keys

```
php magento-key-rotation.php retire-keys [--apply]
```

Overwrites every key line except the latest with `retired-<random>` in `env.php`, keeping the count
and order of lines. Without `--apply` it shows what would change. It runs the `verify` walk first
and refuses, with exit 1, if anything still depends on an older key. With `--apply` it copies
`env.php` to `env.php.bak-<datetime>` with mode 0600 first, then rewrites `env.php`. Keep that
backup off the web server; it still holds the old key. Run `bin/magento cache:flush` afterwards.

### help

```
php magento-key-rotation.php help
```

Prints the option reference to standard output and exits 0.

## Files the tool writes

| File | Written by | Contents |
|---|---|---|
| `FILE` | `re-encrypt --dump=FILE` | One `UPDATE ... WHERE <pk> AND <column>=<old ciphertext> LIMIT 1;` per row, plus a header comment. Executable as is. |
| `FILE.backup.sql` | `re-encrypt --dump=FILE` | The reverse of each statement in `FILE`. Undoes `FILE` only if `FILE` itself was executed. |
| `FILE.unreadable.sql` | `re-encrypt --dump=FILE`, only if needed | Statements that set permanently unreadable values to `NULL`, each preceded by a comment naming the diagnosis. Review, then run by hand. |
| `FILE.unreadable.backup.sql` | same | Restores the values `FILE.unreadable.sql` cleared. |
| `var/re-encrypt-<time>.backup.sql` | `re-encrypt --apply` without `--dump` | The reverse of every row that run wrote. Path is printed in the report; override with `--backup=FILE`. |
| `app/etc/env.php.bak-<datetime>` | `retire-keys --apply` | The `env.php` from before the old keys were overwritten. Mode 0600. |

Nothing else is written. Reports go to standard output; errors and PHP notices go to standard
error, so a report can be piped to a file cleanly.

## Runbook

This is the procedure we follow. Steps 2, 3 and 5 are read-only. Steps 4, 6 and 8 write, and the
whole sequence is done in a maintenance window with a backup taken at step 1.

**0. Patch first.** A rotation on an unpatched store is pointless.

**1. Maintenance mode, then back up.** Copy `env.php` and dump the database. Consider dumping
`core_config_data` separately as well; see *Backups and rollback* below for why.

```
bin/magento maintenance:enable
cp app/etc/env.php app/etc/env.php.before-rotation
mysqldump ... > before-rotation.sql
```

**2. Inventory the code.**

```
php magento-key-rotation.php code-scan
```

Note every extension in the "own crypto" list. Those need their own procedure and their own test
at the end.

**3. Scan the database.**

```
php magento-key-rotation.php scan
```

Read the whole report and work through the "values needing attention" section before going on. A
missing key can be supplied with `--old-key=KEY` on every later command. A truncated or mangled
value has to be re-entered or restored; nothing can recover it from the row. Keep the output.

**4. Add the new key and run Adobe's re-encryptors.**

```
bin/magento encryption:key:change
bin/magento encryption:data:re-encrypt      # 2.4.8+ and the February 2025 patches; skip if absent
```

Do not remove the old key. There is no way back from this step: `core_config_data` is already
re-encrypted and Adobe's command writes no backup.

**5. Rehearse.**

```
php magento-key-rotation.php re-encrypt --dump=rotation.sql
```

Nothing is written. `rotation.sql` holds one `UPDATE` per row that would change,
`rotation.sql.backup.sql` the exact reverse of each, and `rotation.sql.unreadable.sql` the rows that
can never be read again, if any. Read `rotation.sql`.

**6. Apply exactly what you reviewed.**

```
php magento-key-rotation.php re-encrypt --apply --from-dump=rotation.sql
bin/magento cache:flush
```

Rows that changed since the dump are reported as skipped; repeat steps 5 and 6 to catch them. Add
`--allow-binary` if the scan reported binary plaintext.

**7. Verify, then test.**

```
php magento-key-rotation.php verify
```

Do not go past this step until it exits 0. Then place a test order through each payment method,
run each shipping rate lookup, send a transactional email, log into the admin with 2FA, and exercise
every integration.

**8. Retire the old keys.**

```
php magento-key-rotation.php retire-keys --apply
bin/magento cache:flush
```

`env.php` is backed up first as `env.php.bak-<datetime>` with mode 0600. Keep that backup off the
web server; it still holds the old key. On a multi-node setup make sure the new `env.php` reaches
every node. If a cache flush was skipped earlier or a node holds a stale cache, the CLI itself may
fail here because cached values on the old key can no longer be decrypted, so be ready to flush the
cache storage directly. Run the tests from step 7 again.

**9. Rotate the secrets themselves.** Everything the old key protected was readable by whoever had
it. Generate new credentials at the payment gateway, carriers, SMTP provider and every API partner,
reset admin passwords, reissue integration tokens, and handle every extension from the `code-scan`
"own crypto" list by its own procedure.

**10. Scan once more and leave maintenance mode.**

```
php magento-key-rotation.php scan
bin/magento maintenance:disable
```

The report should say that everything is on the latest key and every older line is retired.

## Backups and rollback

Every encryption produces different ciphertext, because each one carries a fresh random nonce. That
has one consequence worth understanding: a reverse file undoes only the exact statements it was
written against.

- `re-encrypt --dump=FILE` (dry run) writes `FILE` and `FILE.backup.sql`. The backup undoes `FILE`
  only if `FILE` itself is what gets executed, by `--apply --from-dump=FILE` or by feeding it to
  `mysql`.
- `re-encrypt --apply` on its own encrypts afresh and writes its own reverse file, by default
  `var/re-encrypt-<time>.backup.sql` under the Magento root. The report prints the path. A dry run's
  backup will not undo this run.
- Every `UPDATE`, forward or reverse, matches the row by primary key and by its current value, so a
  statement whose row has changed affects nothing instead of overwriting it. Rows without a primary
  key are matched by their exact old value, which is unique for the same reason.
- `FILE.unreadable.sql` clears values that can never be decrypted again, after you have reviewed
  it. `FILE.unreadable.backup.sql` restores them.

A full rollback needs three things restored together: the rows this tool changed (the backup SQL),
the rows Adobe's command changed in step 4 (`core_config_data`, from your own dump), and `env.php`
from before the rotation. Restoring `env.php` alone removes the new key and makes every row still on
it unreadable.

## Reading the report

The header lists every key line in `env.php` with its format, its fingerprint, and which line is the
latest. The table that follows shows, per column, how many ciphertexts were found and a breakdown
such as `key0:3=41 key1:3=2 ON-OLD-KEY=41`: forty-one values on key line 0 with cipher 3, two on
line 1, forty-one that need rotating. Other markers on a line:

| Marker | Meaning |
|---|---|
| `embedded=N` | N values whose ciphertext sits inside JSON, serialized PHP or a query string. |
| `nested=N` | N ciphertexts found inside the plaintext of another encrypted value. |
| `cannot-decrypt=N` | N values no available key can read; they block `verify`. |
| `unreadable=N` | N values that are permanently dead (truncated, mangled, retired line); they do not block `verify`. |
| `binary=N` | N values that decrypt to non-text; they need `--allow-binary`. |
| `MALFORMED=N` | N values that start like a ciphertext but do not parse as one. |
| `would_update=N` / `updated=N` | What `re-encrypt` would write, or wrote. |
| `SKIPPED` / `FAILED=N` | Rows left alone because they changed underneath, or could not be decrypted. |
| `no-PK, matched by value` | The table has no primary key; rows are matched by their exact old ciphertext. |

Every value that will not decrypt appears once more under "values needing attention", grouped by
diagnosis code, with the rows it affects and the steps to take.

## Diagnosis codes

| Code | Meaning | Blocks retiring? |
|---|---|---|
| `KEY_MISMATCH` | Cipher 3, and no key in `env.php` (nor `--old-key`) decrypts it. Written with a key that is not there any more. | Yes, until the key is found or the row is cleared. |
| `KEY_LINE_MISSING` | The prefix names a line number higher than `env.php` has. Key lines were deleted. Restore `env.php` with the original line count and order. | Yes. |
| `KEY_INDEX_SHIFTED` | Labelled line N but decrypts with the key on another line: `env.php` lines were reordered. Repair the order, or pass that key as `--old-key`. | Yes. |
| `KEY_LINE_UNUSABLE` | The line it names does not decode to a 32-byte key: a truncated or wrapped value in `env.php`. | Yes. |
| `KEY_RETIRED` | The line it names was overwritten by `retire-keys`. Missed by an earlier rotation. Put the real key back on that line to recover it; otherwise dead. | No. |
| `PAYLOAD_TRUNCATED` | Too few bytes to be a cipher-3 value, typically cut off by a column that was too narrow. Not recoverable from the row. | No. Offered in `.unreadable.sql`. |
| `PAYLOAD_NOT_BASE64` | Characters outside the base64 alphabet: mangled by a charset-mismatched import or an editor. Restore from a backup. | No. Offered in `.unreadable.sql`. |
| `MALFORMED` | Matched the search but does not parse as `key:cipher:base64`. Usually ordinary data. | No. Offered in `.unreadable.sql`; use `--exclude` for false positives. |
| `BINARY_PLAINTEXT` | Decrypts correctly, but to non-text (certificates, keys, compressed data). Not a failure. Re-encrypt with `--allow-binary`. | Yes, until moved. |
| `EMPTY_PLAINTEXT` | Decrypts to an empty string. The key is right; the secret was empty. Moved like any other value. | No. |
| `MCRYPT_MISSING` | Cipher 0, 1 or 2 (pre-2.1 mcrypt) and this PHP has neither the extension nor the polyfill. Install `phpseclib/mcrypt_compat` on a copy and re-run there. | Yes. |
| `LEGACY_WRONG_KEY` | mcrypt value that produced nothing usable with the key on its line. `--old-key` does not help for mcrypt; the key must be on the right line. | Yes. |
| `LEGACY_GARBAGE` | mcrypt value that decrypts to garbage, which is what a wrong key looks like without an authentication tag. Do not `--allow-binary` these. | No. Offered in `.unreadable.sql`. |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Done. For `verify`: PASS. For `re-encrypt`: every value that needed moving was moved. |
| 1 | Needs attention. `verify` FAIL, `retire-keys` refused, `explain` could not decrypt, `re-encrypt` skipped or could not decrypt some rows, `--from-dump` skipped statements. |
| 2 | Could not start: unknown command, bad option value, missing or unreadable file, no `env.php`, no database connection. |

## What this tool does not do

- It cannot rotate data encrypted by an extension with its own crypto. `code-scan` tells you which
  extensions those are; the rest is up to that extension.
- It does not rotate the secrets at their source. After the key is rotated, the credentials it
  protected still have to be reissued.
- It skips tables above `--max-rows` if you set it, and says so in the report. A report with skipped
  tables is not a full inventory.
- Values encrypted before Magento 2.1 (prefix `0:0`, `0:1`, `0:2`) need mcrypt or the polyfill to
  be decrypted.
- It does not look inside files. Secrets that an extension keeps encrypted on disk, or in a cache
  backend, are outside its view.

## The 2024 script

`update-encryption.php` is the original tool from July 2024, written in the days after CosmicSting
when Adobe's admin page was the only way to change the key and it re-encrypted only the
configuration values declared with the `Encrypted` backend model. It is kept in this repository for
reference and for anyone who has it wired into a procedure already. Use `magento-key-rotation.php`
for anything new.

What it did, and how the new script maps onto it:

| 2024 command | What it did | Now |
|---|---|---|
| `scan` | Walked every table for values starting with `N:N:` and wrote them to a CSV, with `--decrypt --re-encrypt --key=NEW_KEY` to include the decrypted and re-encrypted forms. | `scan`, which also finds embedded and nested values and diagnoses failures. Nothing is written to disk. |
| `update-table --table=T --id-field=F --field=C --key=NEW_KEY --key-index=N --old-key-index=M [--dump=FILE] [--dry-run]` | Re-encrypted one column of one table with a key you passed on the command line. | `re-encrypt`, which does every table and column in one pass and takes the keys from `env.php`. |
| `update-record --table=T --id-field=F --id=N --field=C --key=NEW_KEY` | Re-encrypted a single row. | `re-encrypt --tables=T`, or `encrypt` to produce one value and paste it in. |
| `decrypt-value --table=T --field=C --id=N [--key=KEY]` | Printed the plaintext of one row. | `explain --table=T --column=C --id=N --reveal`. |

Its known limitations, all addressed in the new script: it used `fetchAll` on every table; it saw
only whole values and missed ciphertext inside JSON, serialized data and other encrypted values; it
understood only sodium and skipped mcrypt values without saying so; it skipped anything it could not
decrypt without explaining why; it took the key as a raw 32-character string and so does not
understand 2.4.7 base64 keys; it had no verification step and no safe way to retire a key; and its
`--dump` backup file could not undo a later `--apply`, because every encryption produces different
ciphertext.

## Alternative solutions

For a Magento-module-based approach, see the
[Gene Commerce Encryption Key Manager](https://github.com/genecommerce/module-encryption-key-manager/).

## Contributing

Contributions are welcome. Fork the repository and open a pull request, or open an issue.

## License

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
