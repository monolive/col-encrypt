#!/usr/bin/python

# Crypto module
from Crypto.PublicKey import RSA
from Crypto import Random

import argparse

def parsing_options():
  parser = argparse.ArgumentParser()
  parser.add_argument('-f', '--file', action='store', dest='file', help='filename for keys')
  results = parser.parse_args()
  return results

def main():
  arg = parsing_options()
  random_generator = Random.new().read
  key = RSA.generate(1024, random_generator)
  pub_key = key.publickey()
  with open(arg.file + 'pub', 'w') as pubkey, open(arg.file + 'private', 'w') as prikey:
    hdfscli.write('[global]')
    hdfscli.write('default.alias = hadoop')
    hdfscli.write('[hadoop.alias]')
    prikey.write(key.exportKey().decode())
    pubkey.write(pub_key.exportKey().decode())


if __name__ == "__main__":
    main()
  