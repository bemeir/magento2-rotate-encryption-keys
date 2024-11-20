<?php

/**
 * This code is licensed under the MIT License.
 *
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

if (!isset($argv[1]) || !in_array($argv[1], ['scan', 'update-table', 'update-record', 'decrypt-value'])) {
$usage =<<<END
Usage:
   php update-encryption.php [scan|update-table|update-record|decrypt-value] [OPTIONS]

   General options:
   --key=NEW_KEY             key to use for re-encryption. If used with decrypt-value, this key will be used for decryption
   --key-number=NUMBER       key number to use for re-encryption, default is 1. This means that re-encrypted records will start with 1:3 and new encryption key should be the second
                             in env.php
   --magento-root=PATH       Path to the Magento root folder. Current folder is default
   --old-key=KEY             Normally the script uses key from the current env.php to decrypt values, but --old-key may override it
   --old-key-number=Number   Key number to use for decryption. Default 0


   scan options:
   --output=FILE             A .csv file used to write a list of encrypted fields identified by the scan
   --decrypt                 A flag, default 0. If specified, will write decrypted values in the output file (this is NOT SECURE!)
   --re-encrypt              A flag, default 0. If specified, will write re-encrypted values in the output file
   --ignore-tables           A list of comma-separated tables to ignore, like --ignore-tables=sales_order_entity,sales_order_item

   EXAMPLE: php update-encryption.php scan --output=encrypted-values.csv 

   update-table options:
   --key=KEY             A key used to re-encrypt
   --key-number=NUMBER   Number used to re-encrypt, default 1
   --dry-run             A flag. When specified will not update a database, default 0. Highly recommended to use
   --dump=FILE           File to write UPDATE statements that will update encrypted field. When specified a second file started with 'backup-' will also be created and include
                         the same exact statements, but with the current values, to allow backups. Higly recommended to use
   --table=TABLE         Table to update
   --field=FIELD         Field to re-encrypt
   --id-field=FIELD      Id field. Optional, if missed the script will try to use PRIMARY KEY, if possible

   EXAMPLE: php update-encryption.php update-table --table=core_config_data --field=value --dry-run --dump=rotation.sql --key=NEW_KEY

   update-record options:
   --key=KEY             A key used to re-encrypt
   --key-number=NUMBER   Number used to re-encrypt, default 1
   --dry-run             A flag. When specified will not update a database, default 0. Highly recommended to use
   --dump=FILE           File to write UPDATE statements that will update encrypted field. When specified a second file started with 'backup-' will also be created and include
                         the same exact statements, but with the current values, to allow backups. Higly recommended to use
   --table=TABLE         Table to update
   --field=FIELD         Field to re-encrypt
   --id-field=FIELD      Id field. Optional, if missed the script will try to use PRIMARY KEY, if possible
   --id=ID               The value of the id field to update

   decrypt-value options:
   --value=VALUE         Value to decrypt. Optional.
   --table=TABLE         If value is missing, the table must be specified
   --field=FIELD         If value is missing, the field to decrypt must be specified
   --id=ID               If value is missing, the id (value of a primary key) must be specified
   --key=KEY             If specified, use this key to decrypt

   EXAMPLE: php update-encryption.php decrypt-value --table=core_config_data --field=value --id=1234 --key=KEY_TO_DECRYPT
END;
exit($usage);
}

$command = $argv[1];
$params = [
    'decrypt'        => false,
    're-encrypt'     => false,
    'dry-run'        => false,
    'dump'           => false,
    'magento-root'   => __DIR__,
    'key-number'     => 1,
    'old-key-number' => 0,
    'output'         => 'encrypted-values.csv'
];


foreach ($argv as $i => $argument) {
    if ($i == 0 || $i == 1)
        continue;
    if ($argument == '--decrypt') {
        $params['decrypt'] = true;
    } else if ($argument == '--re-encrypt') {
        $params['re-encrypt'] = true;
    } else if ($argument == '--dry-run') {
        $params['dry-run'] = true;
    } else if (preg_match('%--output=(.*?)$%', $argument, $m)) {
        $params['output'] = $m[1];
    } else if (preg_match('%--key=(.*?)$%', $argument, $m)) {
        $params['key'] = $m[1];
    } else if (preg_match('%--key-number=(\d+?)$%', $argument, $m)) {
        $params['key-number'] = (int)$m[1];
    } else if (preg_match('%--old-key=(.*?)$%', $argument, $m)) {
        $params['old-key'] = $m[1];
    } else if (preg_match('%--old-key-number=(\d+?)$%', $argument, $m)) {
        $params['old-key-number'] = (int)$m[1];
    } else if (preg_match('%--id-field=(.*?)$%', $argument, $m)) {
        $params['id-field'] = $m[1];
    } else if (preg_match('%--field=(.*?)$%', $argument, $m)) {
        $params['field'] = $m[1];
    } else if (preg_match('%--table=(.*?)$%', $argument, $m)) {
        $params['table'] = $m[1];
    } else if (preg_match('%--id=(.*?)$%', $argument, $m)) {
        $params['id'] = $m[1];
    } else if (preg_match('%--dump=(.*?)$%', $argument, $m)) {
        $params['dump'] = $m[1];
    } else if (preg_match('%--magento-root=(.*?)$%', $argument, $m)) {
        $params['magento-root'] = $m[1];
    } else if (preg_match('%--value=(.*?)$%', $argument, $m)) {
        $params['value'] = $m[1];
    } else if (preg_match('%--ignore-tables=(.*?)$%', $argument, $m)) {
        $params['ignore-tables'] = $m[1];
    }

}

if (!file_exists($params['magento-root'] . '/app/etc/env.php')) {
    exit("Run the script from the magento root folder");
}

require $params['magento-root'] . '/vendor/autoload.php';

$env    = include $params['magento-root'] . '/app/etc/env.php';
$config = $env['db']['connection']['default'];
$db     = new \PDO(sprintf('mysql:host=%s;dbname=%s;', $config['host'], $config['dbname']), $config['username'], $config['password']);
$key    = isset($params['old-key']) && $params['old-key'] ? $params['old-key'] : $env['crypt']['key'];
$keyLines = explode("\n", $key);
if (!isset($params['old-key']) && is_array($keyLines)) {
    if (isset($keyLines[$params['old-key-number']]))
        $key = $keyLines[$params['old-key-number']];
    else
        exit("OLD KEY NUMBER IS WRONG, NO KEY WITH NUMBER " . $params['old-key-number'] . " FOUND IN app/etc/env.php\n");

}

$crypt = new \Magento\Framework\Encryption\Adapter\SodiumChachaIetf($key);
if (isset($params['key']) && $params['key'])
    $cryptNew = new \Magento\Framework\Encryption\Adapter\SodiumChachaIetf($params['key']);

function message($message) {
    echo $message . "\n";
}

function definePrimaryKeyField($db, $table)
{
    $metaInfo = $db->query("DESC `$table`")->fetchAll(PDO::FETCH_ASSOC);
    foreach ($metaInfo as $row) {
        if ($row['Key'] == 'PRI') {
            return $row['Field'];
        }
    }
    return null;
}

function decrypt($encrypted, $key, $keyNumber = null)
{
    $chunks = explode(':', $encrypted);
    $value     = null;
    $decryptor = null;
    $keyNumber = null;

    $numberOfChunks = count($chunks);
    if ($numberOfChunks === 4) {
        $keyNumber    = $chunks[0];
        $cryptVersion = $chunks[1];
        if ($cryptVersion != 2) {
            message("UNSUPPORTED FORMAT: $encrypted. Value has four chunks, but second chunk (crypt version) is not 2 (mcrypt, MCRYPT_RIJNDAEL_256)");
            return;
        }
        if (!function_exists('mdecrypt_generic')) {
            message("Unable to decrypt value encrypted with mcrypt because mcrypt extension is not installed.");
            return null;
        }
        $value     = $chunks[3];
        $iv        = $chunks[2] ?? null;
        $decryptor = new \Magento\Framework\Encryption\Adapter\Mcrypt($key, MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC, $iv);
    } else if ($numberOfChunks === 3) {
        $keyNumber    = $chunks[0];
        $cryptVersion = $chunks[1];
        $value        = $chunks[2];
        if ($cryptVersion != 2 && $cryptVersion != 3) {
            message("UNSUPPORTED FORMAT: $encrypted. Value has three chunks, but second chunk (crypt version) is not 2 or 3 (mcrypt MCRYPT_RIJNDAEL_256 or sodium)");
            return;
        }
        if ($cryptVersion == 2 && !function_exists('mdecrypt_generic')) {
            message("Unable to decrypt value encrypted with mcrypt because mcrypt extension is not installed.");
            return null;
        }

        $decryptor = $cryptVersion === 2 ?
                   new \Magento\Framework\Encryption\Adapter\Mcrypt($key, MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC, null) :
                   new \Magento\Framework\Encryption\Adapter\SodiumChachaIetf($key);
    } else if ($numberOfChunks === 2) {
        //very strange format, but allowed by Magento
        $cryptVersion = $chunks[0];
        $value        = $chunks[1];
        if ($cryptVersion != 2 && $cryptVersion != 3) {
            message("UNSUPPORTED FORMAT: $encrypted. Value has three chunks, but second chunk (crypt version) is not 2 or 3 (mcrypt MCRYPT_RIJNDAEL_256 or sodium)");
            return;
        }
        if ($cryptVersion == 2 && !function_exists('mdecrypt_generic')) {
            message("Unable to decrypt value encrypted with mcrypt because mcrypt extension is not installed.");
            return null;
        }

        $decryptor = $cryptVersion === 2 ?
                   new \Magento\Framework\Encryption\Adapter\Mcrypt($key, MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC, null) :
                   new \Magento\Framework\Encryption\Adapter\SodiumChachaIetf($key);
    }
    return $decryptor->decrypt(base64_decode($value));
}

if ($command == 'scan') {
    $encryptedFields = [];
    $tablesToExclude = ["%^catalog%", "%amasty_xsearch_users_search%", "%url_rewrite%", "%amasty_merchandiser_product_index_eav_replica%"];
    $tables = $db->query("SHOW TABLES")->fetchAll();
    $f = fopen($params['output'], 'w');
    fputcsv($f, ['table', 'id_field', 'id value', 'path', 'field', 'value', 'decrypted', 're-encrypted']);
    $ignoreTables = isset($params['ignore-tables']) ? explode(',', $params['ignore-tables']) : [];
    foreach ($tables as $tableRow) {
        $table = $tableRow[0];
        $skipTable = false;
        foreach ($tablesToExclude as $pattern) {
            if (preg_match($pattern, $table)) {
                $skipTable = true;
                break;
            }
        }
        if ($ignoreTables && in_array($table, $ignoreTables)) {
            message("Ignoring table $table");
            $skipTable = true;
        }
        if ($skipTable)
            continue;

        if ( ($idField = definePrimaryKeyField($db, $table)) === null) {
            message("SKIPPING TABLE $table, because no primary key was identified");
            continue;
        }

        $data = $db->query("SELECT * FROM `$table`");
        if (!$data)
            continue;
        while( ($row = $data->fetch(PDO::FETCH_ASSOC)) !== false ) {
            $idValue = $row[$idField];
            foreach ($row as $fieldName => $value) {
                if (($value !== null) && preg_match("%^\d\:\d\:%", $value)) {
                    $chunks      = explode(':', $value);
                    $decrypted   = 'N/A';
                    $reEncrypted = 'N/A';
                    $path        = preg_match('%core_config_data$%', $table) ? $row['path'] : 'N/A';
                    if ($params['decrypt']) {
                        $decrypted = decrypt($value, $key);
                    }
                    if ($params['re-encrypt'] && isset($params['key'])) {
                        $reEncrypted = sprintf("%d:3:%s", $params['key-number'], base64_encode($cryptNew->encrypt($decrypted)));
                    }
                    $update = [
                        $table, $idField, $idValue, $path, $fieldName, $value, $decrypted, $reEncrypted
                    ];
                    fputcsv($f, $update);
                    $encryptedField = sprintf("$table::$fieldName");
                    if (!in_array($encryptedField, $encryptedFields)) {
                        $encryptedFields[] = $encryptedField;
                    }
                }
            }
        }

    }
    print_r($encryptedFields);
} else if ($command == 'update-table' || $command == 'update-record') {
    if (!isset($params['table']))
        exit("--table option is required");
    if (!isset($params['key']))
        exit("--key option is required");
    if (!isset($params['id-field']) && !($params['id-field'] = definePrimaryKeyField($db, $params['table'])))
        exit("--id-field option is missing and auto definition of a primary key failed");
    if (!isset($params['field']))
        exit("--field option is required");
    if (isset($params['id']) && $command == 'update-table')
        exit("Use update-record command to update a single record");

    $idField = $params['id-field'];
    $table   = $params['table'];
    $field   = $params['field'];

    message("Rotating key for a table $table, field $field. Using $idField as primary key.");

    $keyNumber    = $params['old-key-number'];
    $recordFilter = '';
    if ($command == 'update-record'  && isset($params['id']) && ($id = (int)$params['id']) > 0)
        $recordFilter = sprintf(" AND `%s`='%d'", $idField, $id);
    $query = sprintf("SELECT * FROM `%s` WHERE `%s` LIKE '%d:3%%' OR `%s` LIKE '%d:2%%' %s", $table, $field, $keyNumber, $field, $keyNumber, $recordFilter);
    message($query);
    $data = $db->query($query);

    $fileHandler = null;
    $backupHandler = null;
    if (isset($params['dump']) && $params['dump']) {
        $fileHandler   = fopen($params['dump'], 'a');
        $backupHandler = fopen($params['dump'] . '.bckp', 'a');
    }
    while ( ($row = $data->fetch(PDO::FETCH_ASSOC)) !== false) {
        $value = $row[$field];
        $decrypted   = decrypt($value, $key);
        if (empty($decrypted)) {
            message("ERROR - unable to decrypt value '$value', for the record with $idField=" . $row[$idField] . ". Skipping...");
            continue;
        }
        $reEncrypted = sprintf("%d:3:%s", $params['key-number'], base64_encode($cryptNew->encrypt($decrypted)));

        $updateQuery = sprintf("UPDATE `%s` SET `%s`='%s' WHERE `%s`='%d' LIMIT 1;", $table, $field, $reEncrypted, $idField, $row[$idField]);
        $backupQuery = sprintf("UPDATE `%s` SET `%s`='%s' WHERE `%s`='%d' LIMIT 1;", $table, $field, $value, $idField, $row[$idField]);

        if (isset($params['dump']) && $params['dump']) {
            fwrite($fileHandler, $updateQuery . "\n");
            fwrite($backupHandler, $backupQuery . "\n");
        }
        message($updateQuery);
        if (!isset($params['dry-run']) || !$params['dry-run']) {
            $db->query($updateQuery);
            message("  Done");
        }
    }
} else if ($command == 'decrypt-value') {
    $value = null;
    if (isset($params['value'])) {
        $value = $params['value'];
    } else if (isset($params['table']) && isset($params['field']) && isset($params['id'])) {
        $idField = definePrimaryKeyField($db, $params['table']);
        $record = $db->query(sprintf("SELECT * FROM `%s` WHERE %s=%d", $params['table'], $idField, (int)$params['id']))->fetchAll();
        if ($record && isset($record[0])) {
            $value = $record[0][$params['field']];
        }
    }
    $keyToDecrypt = isset($params['key']) ? $params['key'] : $key;
    message("Decrypted value=" . decrypt($value, $keyToDecrypt));
}
