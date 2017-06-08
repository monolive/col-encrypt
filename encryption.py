#!/usr/bin/python

import base64
import M2Crypto
import argparse
import hashlib
import csv
import itertools

publicKey='/home/orenault/Developments/col-encrypt/keys/public_key.pem'
privateKey='/home/orenault/Developments/col-encrypt/keys/private_key.pem'

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

def encrypt_value(to_encrypt, pubRSA):
  CipherText = pubRSA.public_encrypt(to_encrypt, M2Crypto.RSA.pkcs1_oaep_padding)
  return CipherText.encode('base64')

def decrypt_value(to_decrypt, privateRSA):
  try:
    PlainText = privateRSA.private_decrypt(to_decrypt.decode('base64'), M2Crypto.RSA.pkcs1_oaep_padding)
  except:
    print "Error: wrong key?"
    PlainText = ""
  return PlainText

def main():
  arg = parsing_options()
  with open(arg.file + '.enc', 'wb') as fresults, open(arg.file) as fsource:
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
    writeRSA = M2Crypto.RSA.load_pub_key(publicKey)
    readRSA = M2Crypto.RSA.load_key(privateKey)

    for row in reader:      
      for col in columns:
        hashed = hash_value(row[col])
        encrypted = encrypt_value(row[col],writeRSA)
#        enc_dec_value(row[col],writeRSA,readRSA) 
        row[col] = hashed
        row.append(encrypted)
      writer.writerow(row)
    fresults.close()
    fsource.close()

  with open(arg.file + '.enc') as fsource, open(arg.file + '.dec', 'wb') as fdecrypt:
#   # CSV File operations
    reader = csv.reader(fsource, delimiter=arg.delimiter)
    writer = csv.writer(fdecrypt, delimiter=arg.delimiter)
    next(reader)
#   readRSA = M2Crypto.RSA.load_key(privateKey)
    for row in reader:
      print row[7]
      decrypted = decrypt_value(row[7],readRSA)
      #print decrypted
      row[7] = decrypted
      writer.writerow(row)
    fresults.close()
    fsource.close()

if __name__ == "__main__":
  main()
  