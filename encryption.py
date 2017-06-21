#!/usr/bin/python

import base64
import M2Crypto
import argparse
import hashlib
import pandas as pd
import itertools
import sys

def parsing_options():
  parser = argparse.ArgumentParser()
  parser.add_argument('-f', '--file', action='store', dest='file', help='file path', required=True)
  parser.add_argument('-d', '--delimiter', action='store', dest='delimiter', help='field delimiter (default: %(default)s)', default=":" )
  parser.add_argument('-c', '--column', action='append', nargs='+', type=int, dest='column', help='column to encode - can be used multiple times', required=True)
  parser.add_argument('-k', '--key', action='store', dest='RSAkey', help='key to encrypt / decrypt column', required=True)
  parser.add_argument('-o', '--operation', choices=['encrypt', 'decrypt'], dest='operation', default='encrypt', help='operation: encrypt and hash or decrypt')
  parser.add_argument('--header', action='store', dest='header', type=int, help='header row (int) - do not specify if no header', default='0')
  #parser.print_help()
  try:
    results = parser.parse_args()
  except SystemExit as err:
    if err.code == 2: 
      parser.print_help()
    sys.exit(0)
  
  if results.header == 0:
    results.header = None
  else:
    results.header = results.header - 1

  # Check arg
  if results.operation == 'encrypt':
    print "\nData will be hashed and encrypted"
    print "=================================\n"
  else:
    print "\nData will be decrypted"
    print "======================\n"
  return results


def hash_value(to_hash):
  hashed = hashlib.sha256(to_hash).hexdigest()
  return hashed

def encrypt_value(to_encrypt, pubRSA):
  CipherText = pubRSA.public_encrypt(to_encrypt, M2Crypto.RSA.pkcs1_oaep_padding)
  return CipherText.encode('base64')

def decrypt_value(to_decrypt, privateRSA):
  privateRSA = M2Crypto.RSA.load_key(arg.RSAkey)
  try:
    PlainText = privateRSA.private_decrypt(to_decrypt.decode('base64'), M2Crypto.RSA.pkcs1_oaep_padding)
  except:
    print "Error: wrong key?"
    PlainText = ""
  return PlainText

def file_extension(operation):
  if operation == 'decrypt':
    file_ext = ".decrypted"
  else:
    file_ext = ".encrypted"
  return(file_ext)

def get_key(keyfile,operation):
  if operation == 'decrypt':
    key = M2Crypto.RSA.load_key(keyfile)
  else:
    key = M2Crypto.RSA.load_pub_key(keyfile)
  return(key)

def decrypt(to_decrypt, privateRSA):
  try:
    PlainText = privateRSA.private_decrypt(to_decrypt.item().decode('base64'), M2Crypto.RSA.pkcs1_oaep_padding)
  except:
    print "Error: wrong key?"
    PlainText = ""
  return PlainText

def encrypt(to_encrypt, publicRSA):
  CipherText = publicRSA.public_encrypt(to_encrypt.item(), M2Crypto.RSA.pkcs1_oaep_padding)
  return CipherText.encode('base64')

def main():
  arg = parsing_options()
  fext = file_extension(arg.operation)

  # Open output file
  with open(arg.file + fext, 'wb') as fresults:
    # Load file in dataframe

    df=pd.read_csv(arg.file, sep=arg.delimiter, header=arg.header)
    header=[]
    for i in xrange(len(df.columns)):
      header.append( i )
    df.columns = header
    print df.head(1)
    # Flatten the list of columns
    columns = list(itertools.chain.from_iterable(arg.column))
    print columns
    # open RSA key
    key = get_key(arg.RSAkey,arg.operation)

    # Extract columns which need to be hashed / encrypted
    cols = df.iloc[:,columns]

    if arg.operation == 'decrypt':
      # Do not forget the comma behind the privateRSA
      # the correct python grammer for a singleton tuple is (1,) not (1), which is just an
      # expr wth the value 1. 
      df[columns]=cols.apply(decrypt, args=(key,), axis=1)
      df.to_csv(fresults, sep=":", header=arg.header, index=False)
    else:
      #for col in columns:
      #  df[col] = cols.applymap(hash_value).values
      df[columns] = cols.applymap(hash_value).values
      df=df.assign(tes=(cols.apply(encrypt, args=(key,), axis=1)).values)
      df.to_csv(fresults, sep=":", header=arg.header, index=False)

  fresults.closed

def old_main():
    # CSV File operations
    reader = csv.reader(fsource, delimiter=arg.delimiter)
    writer = csv.writer(fresults, delimiter=arg.delimiter)

    # Flatten list of list into a single list
    columns = list(itertools.chain.from_iterable(arg.column))

    # read header and add columns
    headers = reader.next()
    if arg.operation == "encrypt":      
      # Encryption file operations
      writeRSA = M2Crypto.RSA.load_pub_key(arg.RSAkey)
      for col in columns:
        headers.append(headers[col] + "_ENC")
      writer.writerow(headers)
      for row in reader:      
        for col in columns:
          hashed = hash_value(row[col])
          encrypted = encrypt_value(row[col],writeRSA)
          row[col] = hashed
          row.append(encrypted)
        writer.writerow(row)
    else:
      readRSA = M2Crypto.RSA.load_key(arg.RSAkey)
      for row in reader:
        for col in columns:
          decrypted = decrypt_value(row[col],readRSA)
          #print decrypted
          row[col] = decrypted
        writer.writerow(row)

    fresults.close()
    fsource.close()

if __name__ == "__main__":
  main()
  