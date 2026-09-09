<?php
/**
 * This code is licensed under the MIT License.
 *
 * MIT License
 *
 * Copyright (c) 2026
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * THE ABOVE COPYRIGHT NOTICE AND THIS PERMISSION NOTICE SHALL BE INCLUDED IN ALL
 * COPIES OR SUBSTANTIAL PORTIONS OF THE SOFTWARE.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 */

declare(strict_types=1);

/*
 * ------------------------------------------------------------
 * Magento root
 * ------------------------------------------------------------
 *
 * This script is intended to live in:
 *
 *     <magento-root>/var/update-encryption.php
 *
 * Therefore the Magento root is one directory above this file.
 */

$magentoRoot = dirname(__DIR__);

if (!file_exists($magentoRoot . '/app/etc/env.php')) {
    exit("Could not find app/etc/env.php\n");
}

if (!file_exists($magentoRoot . '/vendor/autoload.php')) {
    exit("Could not find vendor/autoload.php\n");
}

/*
 * ------------------------------------------------------------
 * Usage
 * ------------------------------------------------------------
 */

if (
    !isset($argv[1])
    || !in_array(
        $argv[1],
        ['scan', 'update-table', 'update-record'],
        true
    )
) {
    exit(
        "Usage:\n" .
        "  php var/update-encryption.php scan --key-number=NUMBER [--output=FILE] [--decrypt] [--re-encrypt]\n" .
        "  php var/update-encryption.php update-table --table=TABLE --field=FIELD --id-field=ID_FIELD --key-number=NUMBER [--dump=FILE] [--dry-run]\n" .
        "  php var/update-encryption.php update-record --table=TABLE --field=FIELD --id-field=ID_FIELD --id=ID --key-number=NUMBER [--dump=FILE] [--dry-run]\n"
    );
}

$command = $argv[1];

$params = [
    'decrypt'    => false,
    're-encrypt' => false,
    'dry-run'    => false,
    'key-number' => null,
    'output'     => 'encrypted-values.csv',
];

/*
 * ------------------------------------------------------------
 * Parse arguments
 * ------------------------------------------------------------
 */

foreach ($argv as $i => $argument) {
    if ($i === 0 || $i === 1) {
        continue;
    }

    if ($argument === '--decrypt') {
        $params['decrypt'] = true;

    } elseif ($argument === '--re-encrypt') {
        $params['re-encrypt'] = true;

    } elseif ($argument === '--dry-run') {
        $params['dry-run'] = true;

    } elseif (preg_match('/--output=(.*?)$/', $argument, $m)) {
        $params['output'] = $m[1];

    } elseif (preg_match('/--key-number=(\d+)$/', $argument, $m)) {
        $params['key-number'] = (int)$m[1];

    } elseif (preg_match('/--id-field=(.*?)$/', $argument, $m)) {
        $params['id-field'] = $m[1];

    } elseif (preg_match('/--field=(.*?)$/', $argument, $m)) {
        $params['field'] = $m[1];

    } elseif (preg_match('/--table=(.*?)$/', $argument, $m)) {
        $params['table'] = $m[1];

    } elseif (preg_match('/--id=(.*?)$/', $argument, $m)) {
        $params['id'] = $m[1];

    } elseif (preg_match('/--dump=(.*?)$/', $argument, $m)) {
        $params['dump'] = $m[1];
    }
}

if ($params['key-number'] === null) {
    exit("--key-number is required\n");
}

/*
 * ------------------------------------------------------------
 * Load Magento classes
 * ------------------------------------------------------------
 */

require $magentoRoot . '/vendor/autoload.php';

require $magentoRoot .
    '/vendor/magento/framework/Encryption/Adapter/EncryptionAdapterInterface.php';

require $magentoRoot .
    '/vendor/magento/framework/Encryption/Adapter/SodiumChachaIetf.php';

if (file_exists(
    $magentoRoot .
    '/vendor/magento/framework/Encryption/Adapter/Mcrypt.php'
)) {
    require_once $magentoRoot .
        '/vendor/magento/framework/Encryption/Adapter/Mcrypt.php';
}

/*
 * ------------------------------------------------------------
 * Load env.php
 * ------------------------------------------------------------
 */

$env = include $magentoRoot . '/app/etc/env.php';

if (!isset($env['crypt']['key'])) {
    exit("crypt/key was not found in app/etc/env.php\n");
}

/*
 * Magento stores multiple encryption keys as whitespace-separated
 * values. Older versions commonly used newline-separated values.
 *
 * preg_split() mirrors Magento's own Encryptor implementation.
 */

$keyLines = preg_split(
    '/\s+/s',
    trim((string)$env['crypt']['key'])
);

if (!is_array($keyLines) || !$keyLines) {
    exit("No encryption keys found in app/etc/env.php\n");
}

$targetKeyNumber = $params['key-number'];

if (!isset($keyLines[$targetKeyNumber])) {
    exit(
        "KEY NUMBER IS WRONG, NO KEY WITH NUMBER " .
        $targetKeyNumber .
        " FOUND IN app/etc/env.php\n"
    );
}

/*
 * ------------------------------------------------------------
 * Decode Magento key
 * ------------------------------------------------------------
 *
 * Magento 2.4.7+ can store:
 *
 *     base64<base64 encoded 32 byte key>
 *
 * Older Magento versions store the legacy key directly.
 *
 * This mirrors Magento Encryptor::decodeKey().
 */

function decodeMagentoKey(string $key): string
{
    if (strpos($key, 'base64') === 0) {
        $decoded = base64_decode(
            substr($key, strlen('base64'))
        );

        if ($decoded === false) {
            throw new RuntimeException(
                'Unable to Base64 decode Magento encryption key.'
            );
        }

        return $decoded;
    }

    return $key;
}

/*
 * Decode every configured key once.
 *
 * We deliberately never output the actual key.
 */

$keys = [];

foreach ($keyLines as $number => $key) {
    $keys[$number] = decodeMagentoKey($key);
}

echo "\n";
echo "Magento Encryption Key Rotation\n";
echo "================================\n";
echo "Magento root: " . $magentoRoot . "\n";
echo "Encryption keys found:\n";

foreach ($keys as $number => $key) {
    $target = ($number === $targetKeyNumber)
        ? ' [TARGET]'
        : '';

    echo "  Key #{$number}{$target} - "
        . strlen($key)
        . " bytes\n";
}

echo "Target encryption key: #{$targetKeyNumber}\n";
echo "\n";

/*
 * ------------------------------------------------------------
 * Database
 * ------------------------------------------------------------
 */

$config = $env['db']['connection']['default'];

$db = new PDO(
    sprintf(
        'mysql:host=%s;dbname=%s;',
        $config['host'],
        $config['dbname']
    ),
    $config['username'],
    $config['password'],
    [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]
);

/*
 * ------------------------------------------------------------
 * Magento-compatible crypt adapter
 * ------------------------------------------------------------
 *
 * This follows Magento Encryptor::getCrypt():
 *
 *   0 = Blowfish / ECB
 *   1 = Rijndael-128 / ECB
 *   2 = Rijndael-256 / CBC
 *   3 = Sodium ChaCha20-Poly1305
 *
 * For cipher 3, this deliberately uses Magento's own
 * SodiumChachaIetf class — the same adapter used by the
 * original script.
 */

function getCrypt(
    string $key,
    int $cipherVersion,
    ?string $initVector = null
) {
    switch ($cipherVersion) {
        case 3:

            return new \Magento\Framework\Encryption\Adapter\SodiumChachaIetf(
                $key
            );

        case 1:

            if (!defined('MCRYPT_RIJNDAEL_128')) {
                throw new RuntimeException(
                    'MCRYPT_RIJNDAEL_128 is not available in this PHP installation.'
                );
            }

            return new \Magento\Framework\Encryption\Adapter\Mcrypt(
                $key,
                MCRYPT_RIJNDAEL_128,
                MCRYPT_MODE_ECB,
                $initVector
            );

        case 2:

            if (!defined('MCRYPT_RIJNDAEL_256')) {
                throw new RuntimeException(
                    'MCRYPT_RIJNDAEL_256 is not available in this PHP installation.'
                );
            }

            return new \Magento\Framework\Encryption\Adapter\Mcrypt(
                $key,
                MCRYPT_RIJNDAEL_256,
                MCRYPT_MODE_CBC,
                $initVector
            );

        case 0:

            if (!defined('MCRYPT_BLOWFISH')) {
                throw new RuntimeException(
                    'MCRYPT_BLOWFISH is not available in this PHP installation.'
                );
            }

            return new \Magento\Framework\Encryption\Adapter\Mcrypt(
                $key,
                MCRYPT_BLOWFISH,
                MCRYPT_BLOWFISH,
                $initVector
            );

        default:

            throw new RuntimeException(
                "Unsupported Magento cipher version: {$cipherVersion}"
            );
    }
}

/*
 * ------------------------------------------------------------
 * Decrypt Magento value
 * ------------------------------------------------------------
 *
 * This intentionally mirrors Magento Encryptor::decrypt().
 */

function decryptMagentoValue(
    string $value,
    array $keys
): string {
    $parts = explode(':', $value, 4);
    $partsCount = count($parts);

    $initVector = null;

    /*
     * specified key, specified crypt, specified iv
     */
    if ($partsCount === 4) {
        [$keyVersion, $cryptVersion, $iv, $data] = $parts;

        $initVector = $iv
            ? $iv
            : null;

        $keyVersion = (int)$keyVersion;

        /*
         * Magento deliberately treats this format as
         * Rijndael-256.
         */
        $cryptVersion = 2;

    /*
     * specified key, specified crypt
     */
    } elseif ($partsCount === 3) {
        [$keyVersion, $cryptVersion, $data] = $parts;

        $keyVersion = (int)$keyVersion;
        $cryptVersion = (int)$cryptVersion;

    /*
     * no key version, specified crypt
     */
    } elseif ($partsCount === 2) {
        [$cryptVersion, $data] = $parts;

        $keyVersion = 0;
        $cryptVersion = (int)$cryptVersion;

    /*
     * no key version, no crypt version
     */
    } elseif ($partsCount === 1) {
        $keyVersion = 0;
        $cryptVersion = 0;
        $data = $parts[0];

    } else {
        return '';
    }

    if (!isset($keys[$keyVersion])) {
        throw new RuntimeException(
            "Encryption key #{$keyVersion} was not found in env.php."
        );
    }

    $crypt = getCrypt(
        $keys[$keyVersion],
        $cryptVersion,
        $initVector
    );

    $decoded = base64_decode(
        (string)$data,
        true
    );

    if ($decoded === false) {
        throw new RuntimeException(
            'Encrypted value contains invalid Base64 data.'
        );
    }

    /*
     * IMPORTANT:
     *
     * Do not reproduce Sodium's nonce handling here.
     * Magento's SodiumChachaIetf adapter does that itself.
     *
     * This is the same call pattern used by Magento Encryptor.
     */
    return trim(
        $crypt->decrypt($decoded)
    );
}

/*
 * ------------------------------------------------------------
 * Encrypt using target key
 * ------------------------------------------------------------
 *
 * The original script always re-encrypted using cipher 3.
 *
 * We retain that behaviour because Magento's Encryptor::encrypt()
 * also uses SodiumChachaIetf and writes:
 *
 *     key-number:3:base64(payload)
 *
 * If the target installation does not have Sodium, fail rather
 * than silently creating incompatible data.
 */

function encryptMagentoValue(
    string $value,
    int $keyNumber,
    array $keys
): string {
    if (!isset($keys[$keyNumber])) {
        throw new RuntimeException(
            "Target encryption key #{$keyNumber} was not found."
        );
    }

    $crypt = new \Magento\Framework\Encryption\Adapter\SodiumChachaIetf(
        $keys[$keyNumber]
    );

    return sprintf(
        "%d:3:%s",
        $keyNumber,
        base64_encode(
            $crypt->encrypt($value)
        )
    );
}

/*
 * ------------------------------------------------------------
 * SCAN
 * ------------------------------------------------------------
 *
 * This remains read-only.
 *
 * No UPDATE statements are executed anywhere in scan mode.
 */

if ($command === 'scan') {

    /*
     * Store unique encrypted fields along with their detected
     * table, field and ID field so we can generate the update
     * commands automatically.
     */
    $encryptedFields = [];

    /*
     * Keep the exclusions from the original script.
     */
    $tablesToExclude = [
        "%^catalog%",
        "%amasty_xsearch_users_search%",
        "%url_rewrite%",
        "%amasty_merchandiser_product_index_eav_replica%",
    ];

    $tables = $db->query("SHOW TABLES")->fetchAll();

    $outputFile = $params['output'];

    $f = fopen($outputFile, 'w');

    if ($f === false) {
        exit("Unable to open output file: {$outputFile}\n");
    }

    fputcsv(
        $f,
        [
            'table',
            'id_field',
            'id value',
            'path',
            'field',
            'value',
            'status',
            'decrypted',
            're-encrypted',
        ]
    );

    foreach ($tables as $tableRow) {

        /*
         * PDO is using FETCH_ASSOC, so SHOW TABLES returns the
         * table name as the first associative value.
         */
        $table = array_values($tableRow)[0];

        $skipTable = false;

        foreach ($tablesToExclude as $pattern) {
            if (preg_match($pattern, $table)) {
                $skipTable = true;
                break;
            }
        }

        if ($skipTable) {
            continue;
        }

        echo "Scanning {$table}...\n";

        $data = $db
            ->query("SELECT * FROM `$table`")
            ->fetchAll(PDO::FETCH_ASSOC);

        if (!$data) {
            continue;
        }

        foreach ($data as $row) {

            $idField = '';
            $idValue = '';
            $isCoreConfigData = false;

            /*
             * Preserve the original ID/path handling.
             */
            if (preg_match("%core_config_data%", $table)) {

                $idField = 'config_id';
                $idValue = $row['config_id'];
                $isCoreConfigData = true;

            } else {

                foreach ($row as $fieldName => $value) {

                    if (preg_match('%_id$%', $fieldName)) {
                        $idField = $fieldName;
                        $idValue = $value;
                    }
                }
            }

            foreach ($row as $fieldName => $value) {

                if (
                    $value === null
                    || !is_string($value)
                ) {
                    continue;
                }

                /*
                 * Magento encrypted value:
                 *
                 *     key-number:cipher-number:payload
                 *
                 * Validate the complete structure and make sure the
                 * decoded payload is large enough to be a real encrypted
                 * ChaCha20-Poly1305-IETF value.
                 *
                 * This prevents ordinary values such as 00:00:47
                 * from being detected as encrypted.
                 */
                if (
                    preg_match(
                        '/^(\d+):(\d+):(.+)$/',
                        $value,
                        $chunks
                    ) !== 1
                ) {
                    continue;
                }

                $encryptedKeyNumber = (int)$chunks[1];
                $cipherVersion = (int)$chunks[2];
                $payload = $chunks[3];

                if (!isset($keyLines[$encryptedKeyNumber])) {
                    continue;
                }

                if ($cipherVersion !== 3) {
                    continue;
                }

                $decodedPayload = base64_decode(
                    $payload,
                    true
                );

                if ($decodedPayload === false) {
                    continue;
                }

                /*
                 * Sodium ChaCha20-Poly1305-IETF:
                 *
                 * nonce    = 12 bytes
                 * auth tag = 16 bytes
                 *
                 * Therefore the encrypted payload must be at least
                 * 28 bytes.
                 */
                if (strlen($decodedPayload) < 28) {
                    continue;
                }

                $decrypted = '';
                $reEncrypted = '';
                $status = '';

                $path = $isCoreConfigData
                    ? $row['path']
                    : 'N/A';

                /*
                 * Already using target key.
                 */
                if ($encryptedKeyNumber === $targetKeyNumber) {

                    $status = 'ALREADY_TARGET_KEY';

                } else {

                    /*
                     * Only decrypt when requested.
                     *
                     * --re-encrypt implies decryption because the
                     * plaintext is required to create the new value.
                     */
                    if (
                        $params['decrypt']
                        || $params['re-encrypt']
                    ) {

                        try {

                            /*
                             * The embedded key number determines
                             * which key is used for decryption.
                             */
                            $decrypted =
                                decryptMagentoValue(
                                    $value,
                                    $keys
                                );

                            $status = 'DECRYPTED';

                            if ($params['re-encrypt']) {

                                $reEncrypted =
                                    encryptMagentoValue(
                                        $decrypted,
                                        $targetKeyNumber,
                                        $keys
                                    );

                                $status = 'CAN_RE_ENCRYPT';
                            }

                        } catch (Throwable $e) {

                            $status = 'DECRYPT_FAILED';

                            echo "  ERROR "
                                . $table
                                . "."
                                . $fieldName
                                . " ["
                                . $idValue
                                . "]: "
                                . $e->getMessage()
                                . "\n";
                        }

                    } else {

                        $status = 'ENCRYPTED';
                    }
                }

                /*
                 * Never update the DB from scan.
                 */
                fputcsv(
                    $f,
                    [
                        $table,
                        $idField,
                        $idValue,
                        $path,
                        $fieldName,
                        $value,
                        $status,
                        $decrypted,
                        $reEncrypted,
                    ]
                );

                /*
                 * Store the field details once so we can generate
                 * the update-table command at the end of the scan.
                 */
                $encryptedField =
                    sprintf(
                        "%s::%s",
                        $table,
                        $fieldName
                    );

                if (
                    !isset(
                        $encryptedFields[$encryptedField]
                    )
                ) {
                    $encryptedFields[$encryptedField] = [
                        'table' => $table,
                        'field' => $fieldName,
                        'id_field' => $idField,
                    ];
                }
            }
        }
    }

    fclose($f);

    echo "\n";
    echo "Scan complete.\n";
    echo "Output: {$outputFile}\n";
    echo "Target key: #{$targetKeyNumber}\n";
    echo "\n";

    echo "Encrypted fields found:\n";

    foreach ($encryptedFields as $encryptedField) {
        echo "  ["
            . $encryptedField['table']
            . "::"
            . $encryptedField['field']
            . "]"
            . " -- ID field: "
            . $encryptedField['id_field']
            . "\n";
    }

    echo "\n";
    echo "Commands to update these fields:\n";
    echo "\n";

    foreach ($encryptedFields as $encryptedField) {
        echo "php var/update-encryption.php update-table"
            . " --table="
            . $encryptedField['table']
            . " --id-field="
            . $encryptedField['id_field']
            . " --field="
            . $encryptedField['field']
            . " --key-number="
            . $targetKeyNumber
            . " --dry-run"
            . "\n";
    }

    echo "\n";
    echo "IMPORTANT: scan mode is read-only. No database changes were made.\n";

    exit;
}

/*
 * ------------------------------------------------------------
 * UPDATE TABLE / UPDATE RECORD
 * ------------------------------------------------------------
 */

if (
    $command === 'update-table'
    || $command === 'update-record'
) {

    if (!isset($params['table'])) {
        exit("--table option is required\n");
    }

    if (!isset($params['id-field'])) {
        exit("--id-field option is required\n");
    }

    if (!isset($params['field'])) {
        exit("--field option is required\n");
    }

    $idField = $params['id-field'];
    $table = $params['table'];
    $field = $params['field'];

    /*
     * update-record requires --id.
     */
    if (
        $command === 'update-record'
        && !isset($params['id'])
    ) {
        exit("--id option is required for update-record\n");
    }

    /*
     * Build record filter.
     */
    $recordFilter = '';

    if (
        $command === 'update-record'
        && isset($params['id'])
        && ($id = (int)$params['id']) > 0
    ) {
        $recordFilter = sprintf(
            " AND `%s`='%d'",
            $idField,
            $id
        );
    }

    /*
     * We deliberately don't filter by the old key number in SQL.
     *
     * The encrypted value itself tells us which key it uses.
     *
     * This allows:
     *
     *     0:3:...
     *     1:3:...
     *     2:3:...
     *
     * to be handled automatically.
     *
     * The LIKE clause limits this to Magento cipher-3 values,
     * which is the format used by the original script.
     */
    $query = sprintf(
        "SELECT * FROM `%s` WHERE `%s` LIKE '%%:3:%%' %s",
        $table,
        $field,
        $recordFilter
    );

    echo $query . "\n";

    $data = $db
        ->query($query)
        ->fetchAll(PDO::FETCH_ASSOC);

    $fileHandler = null;
    $backupHandler = null;

    if (isset($params['dump'])) {

        $fileHandler =
            fopen(
                $params['dump'],
                'a'
            );

        $backupHandler =
            fopen(
                'backup-' . $params['dump'],
                'a'
            );
    }

    foreach ($data as $row) {

        $value = $row[$field];

        $chunks = explode(':', $value, 3);

        if (count($chunks) !== 3) {
            echo "SKIPPING invalid encrypted value\n";
            continue;
        }

        $oldKeyNumber = (int)$chunks[0];
        $cipherVersion = (int)$chunks[1];

        /*
         * Skip anything that isn't cipher 3.
         */
        if ($cipherVersion !== 3) {
            echo "SKIPPING unsupported cipher {$cipherVersion}\n";
            continue;
        }

        /*
         * Already using target key.
         */
        if ($oldKeyNumber === $targetKeyNumber) {

            echo "SKIPPING row "
                . $idField
                . "="
                . $row[$idField]
                . " - already using target key #"
                . $targetKeyNumber
                . "\n";

            continue;
        }

        try {

            /*
             * Automatically select the old key based on the
             * embedded key number.
             */
            $decrypted =
                decryptMagentoValue(
                    $value,
                    $keys
                );

            /*
             * Encrypt with target key.
             */
            $reEncrypted =
                encryptMagentoValue(
                    $decrypted,
                    $targetKeyNumber,
                    $keys
                );

        } catch (Throwable $e) {

            echo "ERROR row "
                . $idField
                . "="
                . $row[$idField]
                . ": "
                . $e->getMessage()
                . "\n";

            continue;
        }

        echo "UPDATING row "
            . $idField
            . "="
            . $row[$idField]
            . ", "
            . $field
            . "; Old key #"
            . $oldKeyNumber
            . " -> New key #"
            . $targetKeyNumber
            . "\n";

        /*
         * Use PDO prepared statements rather than inserting the
         * encrypted value directly into SQL.
         */
        $updateQuery =
            sprintf(
                "UPDATE `%s` SET `%s`=:value WHERE `%s`=:id LIMIT 1",
                $table,
                $field,
                $idField
            );

        $backupQuery =
            sprintf(
                "UPDATE `%s` SET `%s`=:value WHERE `%s`=:id LIMIT 1",
                $table,
                $field,
                $idField
            );

        /*
         * Keep the original dump/backup behaviour.
         *
         * These are informational SQL statements only; the actual
         * update below uses prepared statements.
         */
        if ($params['dump'] ?? false) {

            fwrite(
                $fileHandler,
                $updateQuery
                . " -- value/key #"
                . $targetKeyNumber
                . "\n"
            );

            fwrite(
                $backupHandler,
                $backupQuery
                . " -- original value\n"
            );
        }

        if (!$params['dry-run']) {

            echo "UPDATING !\n";

            $statement = $db->prepare(
                $updateQuery
            );

            $statement->execute(
                [
                    ':value' =>
                        $reEncrypted,
                    ':id' =>
                        $row[$idField],
                ]
            );

        } else {

            echo "DRY RUN - NOT UPDATING\n";
        }
    }

    echo "\n";
    echo "Complete.\n";

    if ($params['dry-run']) {
        echo "DRY RUN: no database changes were made.\n";
    }

    exit;
}


