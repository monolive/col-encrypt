# col-encrypt
python script to encrypt / decrypt columns from CSV files

The script is using AES for encrypting the data whilst the AES key is being encrypted using RSA.

The RSA key is stored in Azure KeyVault 
The AES keys are being stored in Azure Blob storage.


# How to use it
```
usage: hdfs_crypto.py [-h] [--azure-conf AZURECONF] [--hdfs-conf HDFSCONF] -i
                      INPUT [-o OUTPUT] [-d DELIMITER] -c COLUMN [COLUMN ...]
                      [--header HEADER] [--overwrite] --operation
                      {encrypt,decrypt}

optional arguments:
  -h, --help            show this help message and exit
  --azure-conf AZURECONF
                        file containing azure credentials (default: /etc/hdfs-
                        crypto/conf/azure.conf
  --hdfs-conf HDFSCONF  file containing hdfs info (default: /etc/hdfs-
                        crypto/conf/hdfscli.conf
  -i INPUT, --input INPUT
                        input file path
  -o OUTPUT, --output OUTPUT
                        output file path - default is <input file
                        name>.[encrypted | decrypted]
  -d DELIMITER, --delimiter DELIMITER
                        field delimiter (default: #) - '-' is forbidden
  -c COLUMN [COLUMN ...], --column COLUMN [COLUMN ...]
                        column name to encode - can be used multiple times
  --header HEADER       header row (int) - do not specify if no header
  --overwrite           overwrite output file
  --operation {encrypt,decrypt}
                        operation: encrypt and hash or decrypt
```

# Requirements
You can find the required python modules in requirements.txt


```
[global]
default.alias = prod
autoload.modules = hdfs.ext.kerberos

[prod.alias]
url = http://<namenode.fqdn>:50070

# if kerberos don't set user
# user = renaulto
client = KerberosClient
```


# How to generate an SSL certificate
## Generate private key
`openssl genrsa -out private_key.pem 2048`

## Generate public key
`openssl rsa -in private_key.pem -out public_key.pem -outform PEM -pubout`

## Check your key 
- Encrypt data
`echo toto | openssl rsautl -encrypt -inkey public_key.pem -pubin | base64 > test`

- Decrypt data
`cat test| base64 --decode | openssl rsautl -decrypt -inkey private_key.pem`

`toto`