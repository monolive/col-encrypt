#!/usr/bin/env python
# encoding: utf-8

import itertools
import sys
import argparse
# Read / write HDFS
from hdfs import Config
from hdfs.ext.kerberos import KerberosClient
#Encoding
import base64
# RSA
import M2Crypto
# Hashing algo
import hashlib
# Pandas
import pandas as pd

def parsing_options():
  parser = argparse.ArgumentParser()
  parser.add_argument('-i', '--input', action='store', dest='input', help='input file path', required=True)
  parser.add_argument('-o', '--output', action='store', dest='output', help='output file path - default is <input file name>.[encrypted | decrypted]')
  parser.add_argument('-d', '--delimiter', action='store', dest='delimiter', help='field delimiter (default: %(default)s)', default=":" )
  parser.add_argument('-c', '--column', action='append', nargs='+', type=int, dest='column', help='column to encode - can be used multiple times', required=True)
  parser.add_argument('-k', '--key', action='store', dest='RSAkey', help='key to encrypt / decrypt column', required=True)
  parser.add_argument('--operation', choices=['encrypt', 'decrypt'], dest='operation', default='encrypt', help='operation: encrypt and hash or decrypt')
  parser.add_argument('--header', action='store', dest='header', type=int, help='header row (int) - do not specify if no header', default='0')
  parser.add_argument('--overwrite', action='store_true', dest='overwrite', help='overwrite output file', default='False')  
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

  if results.output is None:
    results.output = output_file_name(results.input, results.operation)

  # Check arg
  if results.operation == 'encrypt':
    print "\nData will be hashed and encrypted"
    print "=================================\n"
  else:
    print "\nData will be decrypted"
    print "======================\n"
  return results

def hash_value(to_hash):
  hashed = []
  for value in to_hash:
    result = hashlib.sha256(value).hexdigest()
    hashed.append(result)
  return hashed

def output_file_name(inputFile, operation):
  if operation == 'decrypt':
    outputFile = inputFile + ".decrypted"
  else:
    outputFile = inputFile + ".encrypted"
  return(outputFile)

def get_key(keyfile,operation):
  if operation == 'decrypt':
    try:
      key = M2Crypto.RSA.load_key(keyfile)
    except:
      print "Error: Wrong key? expecting private key"
      sys.exit(0)
  else:
    try:
      key = M2Crypto.RSA.load_pub_key(keyfile)
    except:
      print "Error: Wrong key? expecting public key"
      sys.exit(0)
  return(key)

def decrypt(to_decrypt, privateRSA):
  decrypted=[]
  for value in to_decrypt:
    try:
      PlainText = privateRSA.private_decrypt(value.decode('base64'), M2Crypto.RSA.pkcs1_oaep_padding)
      decrypted.append(PlainText)
    except:
      print "Error: wrong key? wrong column?"
      PlainText = ""
  return decrypted

def encrypt(to_encrypt, publicRSA):
  encrypted=[]
  #for index, value in enumerate(list(to_encrypt)):
  for value in to_encrypt:
    CipherText = publicRSA.public_encrypt(str(value), M2Crypto.RSA.pkcs1_oaep_padding)
    encrypted.append(CipherText.encode('base64'))
  return encrypted

def main():
  arg = parsing_options()
  client = Config().get_client()
  with client.read(arg.input) as inputFile:
    # Load file in dataframe
    df=pd.read_csv(inputFile, sep=arg.delimiter, header=arg.header)
  inputFile.closed

  # Open output file
  with client.write(arg.output, overwrite=arg.overwrite) as outputFile:
    
    # Flatten the list of columns
    column = list(itertools.chain.from_iterable(arg.column))
    # open RSA key
    key = get_key(arg.RSAkey,arg.operation)

    # Extract columns which need to be hashed / encrypted
    cols = df.iloc[:,column]
    colName = cols.columns

    if arg.operation == 'decrypt':
      # Do not forget the comma behind the privateRSA
      # the correct python grammer for a singleton tuple is (1,) not (1), 
      # which is just an expr wth the value 1.
      df[colName]=df[colName].apply(decrypt, args=(key,), axis=1)
      df.to_csv(outputFile, sep=":", header=True, index=False)
    else:
      # Encrypt then hash - as otherwise we encrypt the hash value
      # Call function encrypt w/ RSAkey - Axis=1 for row
      encrypted = df[colName].apply(encrypt, args=(key,))#, axis=1)

      # Rename header to not clash when merging df + encrypted data frame
      new_column=[]
      #for i in cols.columns:
      for i in colName:
        new_column.append(str(i) + '_ENC')
      encrypted.columns = new_column
      
      # Concatenate both dataframe
      df = pd.concat([df, encrypted], axis=1)

      # Generate a hash
      df[colName] = df[colName].apply(hash_value).values
      
      # Write to file
      df.to_csv(outputFile, sep=":", header=True, index=False)

if __name__ == "__main__":
  main()
  