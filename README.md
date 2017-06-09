# col-encrypt
python script to encrypt / decrypt - CSV files

# How to generate an SSL certificate
## Generate private key
`openssl genrsa -out private_key.pem 2048`

## Generate public key
`openssl rsa -in private_key.pem -out public_key.pem -outform PEM -pubout`

## Check your key 
Encrypt data
`echo toto | openssl rsautl -encrypt -inkey public_key.pem -pubin | base64 > test`

Decrypt data
```cat test| base64 --decode | openssl rsautl -decrypt -inkey private_key.pem
toto
```
