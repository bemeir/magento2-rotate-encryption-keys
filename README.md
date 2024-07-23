# Magento Encryption Key Rotation Tool

## Overview

This script addresses the limitations of Magento's native encryption key rotation functionality, particularly in light of recent security vulnerabilities like CosmicSting. It provides a different approach to re-encrypting sensitive data across Magento databases.

This script was built to aid with https://sansec.io/research/cosmicsting-hitting-major-stores and for merchants facing issues using the Adobe supplied tool.

From the sansec post
> Upgrading is Insufficient
> As we warned in our earlier article, it is crucial for merchants to upgrade or apply the official isolated fix. At this stage however, just patching for the CosmicSting vulnerability is likely to be insufficient.
>
>The stolen encryption key still allows attackers to generate web tokens even after upgrading. Merchants that are currently still vulnerable should consider their encryption key as compromised. Adobe offers functionality out of the box to change the encryption key while also re-encrypting existing secrets.
>
>Important note: generating a new encryption key using this functionality does not invalidate the old key. We recommend manually updating the old key in app/etc/env.php to a new value rather than removing it.

## Disclaimer
This tool is provided as-is, without any warranty. Use at your own risk and always test thoroughly in a non-production environment first.

## Features

- Scans all database tables for encrypted values
- Re-encrypts data using a new encryption key
- Handles core Magento tables and custom third-party extension tables
- Supports multiple encryption keys
- Generates backup of current encrypted values
- Option to update database directly or generate SQL update statements

## Installation

1. Clone this repository or download the `update-encryption.php` script.
2. Place the script in the root directory of your Magento installation.

## Usage

### Step 1: Scan Mode

Run the script in scan mode to identify encrypted values:
This will generate a CSV file listing all tables, fields, and encrypted values found.

```
php update-encryption.php scan
```

We can also do this:

```
php update-encryption.php scan --decrypt --re-encrypt --key=NEW_KEY
```
This will (try to) decrypt all values and write both encrypted with the original key, decrypted and encrypted with the new key values in encrypted-values.csv. You can change filename with --output=FILE command.

### Step 2: Re-encryption

After reviewing the scan results, run the script to re-encrypt the data.
This command DOES  CHANGE  the database!!! Be careful!! Only run it when old encryption key is written in env.php

```
update-encryption.php update-table --table=core_config_data\
      --id-field=config_id --field=value --key=NEW_KEY --key-number=1\
       --old-key-number=[0/1]
       --dump=rotation.sql
       --dry-run
```

Options:
- `--dry-run`: Generate SQL update statements without modifying the database
- `--backup`: Create a backup of current encrypted values before re-encryption

Note --dry-run option, it won’t execute an update query only print it, --dump will write to a file (in the append mode, so you can have the same file for multiple tables), and will also generate a backup file.

You can also update a single record, the command for that will be:

```
php update-encryption.php update-record --table=core_config_data --id-field=config_id --id=1234 --field=value --key=NEW_KEY
```

## Important Notes

- This script is designed for use by experienced Magento developers.
- Always backup your database before running this script.
- The script uses `fetchAll`, which may consume significant memory for large tables.
- Currently only supports Sodium for encryption (legacy mcrypt values are not handled).
- Encrypted values within JSON or URL parameters may be missed.

## Caution

- Do not attempt to decrypt or re-encrypt hashed passwords.
- Be cautious when dealing with payment information and other sensitive data.

## Limitations

- May not catch all encrypted values, especially those embedded in complex data structures.
- Performance may be impacted on very large databases.

## Alternative Solutions

For those preferring a Magento module-based approach, consider:
[Gene Commerce Encryption Key Manager](https://github.com/genecommerce/module-encryption-key-manager/)

## Contributing

Contributions to improve this tool are welcome. Feel free to Fork it and submit pull requests or open issues on the GitHub repository.

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
