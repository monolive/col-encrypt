#!/usr/bin/python

import csv
import argparse

# Use to flatten list
import itertools

# Crypto & Hash module
import hashlib
import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


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
  return str(encrypted)
  #return base64.b64encode(encrypted)

def encrypt_value2(to_encrypt, key):
  encrypted = key.encrypt(to_encrypt,32)
  return str(encrypted)


def main():
  arg = parsing_options()
  with open(arg.file + '.enc', 'wb') as fresults, open(arg.file) as fsource, open(arg.RSAkey, 'r') as public_pem:
    # CSV File operations
    reader = csv.reader(fsource, delimiter=arg.delimiter)
    writer = csv.writer(fresults, delimiter=arg.delimiter)

    # Flatten list of list into a single list
    columns = list(itertools.chain.from_iterable(arg.column))

    # read header and add columns
    headers = reader.next()
    for col in columns:
      headers.append(headers[col] + "_ENC")
    writer.writerow(headers)

    # Encryption file operations
    key = RSA.importKey(public_pem.read())
    cipher = PKCS1_OAEP.new(key)

    for row in reader:      
      for col in columns:
        hashed = hash_value(row[col])
        #encrypted = encrypt_value(row[col],cipher)
        encrypted = encrypt_value2(row[col],key)
        row[col] = hashed
        row.append(encrypted)
      writer.writerow(row)
    fresults.close()
    fsource.close()

if __name__ == "__main__":
  main()
  