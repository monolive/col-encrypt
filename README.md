# col-encrypt
python script to encrypt / decrypt - CSV files

# Gen private key
openssl genrsa -out private_key.pem 1024

# Gen pub key
openssl rsa -in private_key.pem -out public_key.pem -outform PEM -pubout

# Encrypt data
echo toto | openssl rsautl -encrypt -inkey public_key.pem -pubin | base64 > test

# Decrypt data
cat test| base64 --decode | openssl rsautl -decrypt -inkey private_key.pem
toto
