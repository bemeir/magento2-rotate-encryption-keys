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

<?php

if (!file_exists('./app/etc/env.php')) {
    exit("Run the script from the magento root folder");
}
if (!isset($argv[1]) || !in_array($argv[1], ['scan', 'update-table', 'update-record'])) {
    exit("Usage:\n     php update-encryption.php scan --output=[FILE] [--decrypt] [--key=KEY] [--key-number=NUMBER] [--old-key=KEY] [--old-key-number=NUMBER] [--re-encrypt]\n     php update-encryption.php [update-table|update-record] --table=TABLE --field=FIELD --id-field=ID_FIELD --key=KEY [--key-number=NUMBER] [--old-key=KEY] [--old-key-number=NUMBER] [--id=ID] [--dump=FILE] [--dry-run]\n");
}

$command = $argv[1];
$params = [
    'decrypt'    => false,
    're-encrypt' => false,
    'dry-run'    => false,
    'key-number' => 1,
    'old-key-number' => 0,
    'output'     => 'encrypted-values.csv'
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
    }

}

require './vendor/magento/framework/Encryption/Adapter/EncryptionAdapterInterface.php';
require './vendor/magento/framework/Encryption/Adapter/SodiumChachaIetf.php';

$env    = include __DIR__ . '/app/etc/env.php';
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

$crypt    = new \Magento\Framework\Encryption\Adapter\SodiumChachaIetf($key);
if (isset($params['key']) && $params['key'])
    $cryptNew = new \Magento\Framework\Encryption\Adapter\SodiumChachaIetf($params['key']);

if ($command == 'scan') {
    $encryptedFields = [];
    $tablesToExclude = ["%^catalog%", "%amasty_xsearch_users_search%", "%url_rewrite%", "%amasty_merchandiser_product_index_eav_replica%"];
    $tables = $db->query("SHOW TABLES")->fetchAll();
    $f = fopen($params['output'], 'w');
    fputcsv($f, ['table', 'id_field', 'id value', 'path', 'field', 'value', 'decrypted', 're-encrypted']);
    foreach ($tables as $tableRow) {
        $table = $tableRow[0];
        $skipTable = false;
        foreach ($tablesToExclude as $pattern) {
            if (preg_match($pattern, $table)) {
                $skipTable = true;
                break;
            }
        }
        if ($skipTable)
            continue;

        $offset = 0;
        $limit = 1000; // Adjust the chunk size as needed
        $moreRowsAvailable = true;

        while ($moreRowsAvailable) {
            $query = $db->prepare("SELECT * FROM $table LIMIT :offset, :limit");
            $query->bindParam(':offset', $offset, PDO::PARAM_INT);
            $query->bindParam(':limit', $limit, PDO::PARAM_INT);
            $query->execute();
            $data = $query->fetchAll(PDO::FETCH_ASSOC);

            if (!$data) {
                $moreRowsAvailable = false;
            } else {
                foreach ($data as $row) {
                    $idField = '';
                    $idValue = '';
                    $isCoreConfigData = false;
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
                        if (($value !== null) && preg_match("%^\d\:\d\:%", $value)) {
                            $chunks = explode(':', $value);
                            $decrypted = 'N/A';
                            $reEncrypted = 'N/A';
                            $path = $isCoreConfigData ? $row['path'] : 'N/A';
                            if ($params['decrypt'] && isset($params['key'])) {
                                $decrypted = $crypt->decrypt(base64_decode($chunks[2]));
                            }
                            if ($params['re-encrypt'] && isset($params['key'])) {
                                $reEncrypted = sprintf("%d:3:%s", $params['key-number'],
                                    base64_encode($cryptNew->encrypt($decrypted)));
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
                    $offset += $limit;

                }
            }

        }
    }
    fclose($f);
    print_r($encryptedFields);
} else if ($command == 'update-table' || $command == 'update-record') {
    if (!isset($params['table']))
        exit("--table option is required");
    if (!isset($params['key']))
        exit("--key option is required");
    if (!isset($params['id-field']))
        exit("--id-field option is required");
    if (!isset($params['field']))
        exit("--field option is required");
    if (isset($params['id']) && $command == 'update-record')
        exit("Use update-record command to update a single record");

    $idField = $params['id-field'];
    $table   = $params['table'];
    $field   = $params['field'];

    $keyNumber    = $params['old-key-number'];
    $recordFilter = '';
    if ($command == 'update-record'  && isset($params['id']) && ($id = (int)$params['id']) > 0)
        $recordFilter = sprintf(" AND `%s`='%d'", $idField, $id);
    $query = sprintf("SELECT * FROM `%s` WHERE `%s` LIKE '%d:3%%' %s", $table, $field, $keyNumber, $recordFilter);
    echo $query . "\n";

    $offset = 0;
    $limit = 1000; // Adjust the chunk size as needed
    $moreRowsAvailable = true;

    $fileHandler = null;
    $backupHandler = null;
    if ($params['dump']) {
        $fileHandler   = fopen($params['dump'], 'a');
        $backupHandler = fopen('backup-' . $params['dump'], 'a');
    }
    while ($moreRowsAvailable) {
        $query = sprintf("SELECT * FROM `%s` WHERE `%s` LIKE '%d:3%%' %s LIMIT :offset, :limit", $table, $field, $keyNumber, $recordFilter);
        $stmt = $db->prepare($query);
        $stmt->bindParam(':offset', $offset, PDO::PARAM_INT);
        $stmt->bindParam(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();
        $data = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($data as $row) {
            $value = $row[$field];
            $chunks = explode(':', $value);
            $decrypted = $crypt->decrypt(base64_decode($chunks[2]));
            $reEncrypted = sprintf("%d:3:%s", $params['key-number'], base64_encode($cryptNew->encrypt($decrypted)));

            echo "UPDATING row $idField=" . $idField . ", $field=" . $row[$field] . "; New value = " . $reEncrypted . "\n";
            $updateQuery =
                sprintf("UPDATE `%s` SET `%s`='%s' WHERE `%s`='%d' LIMIT 1;", $table, $field, $reEncrypted, $idField,
                    $row[$idField]);
            $backupQuery =
                sprintf("UPDATE `%s` SET `%s`='%s' WHERE `%s`='%d' LIMIT 1;", $table, $field, $value, $idField,
                    $row[$idField]);

            if ($params['dump']) {
                fwrite($fileHandler, $updateQuery . "\n");
                fwrite($backupHandler, $backupQuery . "\n");
            }
            echo "    " . $updateQuery . "\n";
            if (!isset($params['dry-run']) || !$params['dry-run']) {
                echo "UPDATING !\n";
                $db->query($updateQuery);
            }
        }
        $offset += $limit;
    }
    if ($params['dump']) {
        fclose($fileHandler);
        fclose($backupHandler);
    }
}
