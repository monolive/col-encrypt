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
  parser.add_argument('-f', '--file', action='store', dest='file', help='file path', required=True)
  parser.add_argument('-d', '--delimiter', action='store', dest='delimiter', help='field delimiter (default: %(default)s)', default=":" )
  parser.add_argument('-c', '--column', action='append', nargs='+', type=int, dest='column', help='column to encode - can be used multiple times', required=True)
  parser.add_argument('-k', '--key', action='store', dest='RSAkey', help='key to encrypt / decrypt column', required=True)
  parser.add_argument('-o', '--operation', choices=['encrypt', 'decrypt'], dest='operation', default='encrypt', help='operation: encrypt and hash or decrypt')
  parser.add_argument('--header', action='store', dest='header', type=int, help='header row (int) - do not specify if no header', default='0')
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

