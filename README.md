# col-encrypt
python script to encrypt / decrypt - CSV files

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

# How to use it
```
usage: encryption.py [-h] -f FILE [-d DELIMITER] -c COLUMN [COLUMN ...] -k
                     RSAKEY [-o {encrypt,decrypt}] [--header HEADER]

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  file path
  -d DELIMITER, --delimiter DELIMITER
                        field delimiter (default: :)
  -c COLUMN [COLUMN ...], --column COLUMN [COLUMN ...]
                        column to encode - can be used multiple times
  -k RSAKEY, --key RSAKEY
                        key to encrypt / decrypt column
  -o {encrypt,decrypt}, --operation {encrypt,decrypt}
                        operation: encrypt and hash or decrypt
  --header HEADER       header row (int) - do not specify if no header
```

# Requirements
the following python modules are required
 - hdfs
 - requests-kerberos
 - pandas
 - pykerberos
 - M2Crypto

Create /home/<username>/.hdfscli.cfg

[global]

default.alias = prod

autoload.modules = hdfs.ext.kerberos

[prod.alias]

url = http://<namenode.fqdn>:50070

# if kerberos don't set user

# user = renaulto

client = KerberosClient
