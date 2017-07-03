#!/usr/bin/python

import csv
import argparse

# Use to flatten list
import itertools

# Crypto & Hash module
import hashlib
import base64
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


def parsing_options():
  parser = argparse.ArgumentParser()
  parser.add_argument('-f', '--file', action='store', dest='file', help='file path')
  parser.add_argument('-d', '--delimiter', action='store', dest='delimiter', help='field delimiter')
  parser.add_argument('-c', '--column', action='append', nargs='+', type=int, dest='column', help='column to encode - can be used multiple times')
  parser.add_argument('-k', '--key', action='store', dest='RSAkey', help='key to encode / decode column')
  parser.add_argument('--encrypt', action='store_true', dest='encrypt', help='encrypt and hash value')
  parser.add_argument('--decrypt', action='store_false', dest='decrypt', help='decrypt value')
  results = parser.parse_args()
  return results


def hash_value(to_hash):
  hashed = hashlib.sha256(to_hash).hexdigest()
  return hashed

def encrypt_value(to_encrypt, cipher):
  encrypted = cipher.encrypt(to_encrypt)
  return base64.b64encode(encrypted)

def decrypt_value(to_decrypt, cipher):
  decrypted = cipher.decrypt(to_decrypt)
  print decrypted

def main():
  arg = parsing_options()
  with open(arg.file + '.dec', 'w') as fresults, open(arg.file) as fsource, open(arg.RSAkey, 'rb') as private_pem:
    # CSV File operations
    reader = csv.reader(fsource, delimiter=arg.delimiter)
    writer = csv.writer(fresults, delimiter=arg.delimiter)

    # Flatten list of list into a single list
    columns = list(itertools.chain.from_iterable(arg.column))
    # Encryption file operations
    key = RSA.importKey(private_pem.read())
    cipher = PKCS1_OAEP.new(key)
    for row in reader:      
      for col in columns:
        decrypted = decrypt_value(row[col],cipher)
        row[col] = decrypted
      writer.writerow(row)
    fresults.close()
    fsource.close()  
  
if __name__ == "__main__":
    main()
  