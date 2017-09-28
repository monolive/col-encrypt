#!/usr/bin/env python
# encoding: utf-8

# Azure modules
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.resource.resources import ResourceManagementClient
from msrest.exceptions import AuthenticationError

# Azure Keyvault
from azure.keyvault import KeyVaultClient

# Azure blob storage
from azure.storage.file import ContentSettings
from azure.storage.blob import BlockBlobService

# Crypto modules
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Pandas modules
import pandas as pd

# Hash modules
import hashlib

# HDFS modules
from hdfs import Config
from hdfs.ext.kerberos import KerberosClient

# Standard modules
import argparse
import sys
import ConfigParser
import base64
import uuid
import itertools

# Parse command line
def parsing_options():
  parser = argparse.ArgumentParser()
  parser.add_argument('--azure-conf', action='store', dest='azureConf', help='file containing azure credentials (default: %(default)s', required=False, default='/etc/hdfs-crypto/conf/azure.conf')
  parser.add_argument('--hdfs-conf', action='store', dest='hdfsConf', help='file containing hdfs info (default: %(default)s', required=False, default='/etc/hdfs-crypto/conf/hdfscli.conf')
  parser.add_argument('-i', '--input', action='store', dest='input', help='input file path', required=True)
  parser.add_argument('-o', '--output', action='store', dest='output', help='output file path - default is <input file name>.[encrypted | decrypted]')
  parser.add_argument('-d', '--delimiter', action='store', dest='delimiter', help='field delimiter (default: %(default)s) - \'-\' is forbidden', default="#" )
  parser.add_argument('-c', '--column', action='append', nargs='+', dest='column', help='column name to encode - can be used multiple times', required=True)
  parser.add_argument('--header', action='store', dest='header', type=int, help='header row (int) (default: %(default)s) - set to 0 if no header', default='1')
  parser.add_argument('--overwrite', action='store_true', dest='overwrite', help='overwrite output file', default='False')  
  parser.add_argument('--operation', choices=['encrypt', 'decrypt'], dest='operation', required=True, help='operation: encrypt and hash or decrypt')
  
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
  if results.delimiter == '-':
    print "Forbidden delimiter"
    sys.exit(0)
  # Check arg
  if results.operation == 'encrypt':
    print "\nData will be hashed and encrypted"
    print "=================================\n"
  else:
    print "\nData will be decrypted"
    print "======================\n"
  return results

# Provide a default name based upon operation
def output_file_name(inputFile, operation):
  if operation == 'decrypt':
    outputFile = inputFile + ".decrypted"
  else:
    outputFile = inputFile + ".encrypted"
  return(outputFile)

# Generate a Hash value
def hash_value(to_hash):
  hashed = []
  for value in to_hash:
    result = hashlib.sha256(str(value)).hexdigest()
    hashed.append(result)
  return hashed

# Generate AES key
def generate_aes_key():
	key = get_random_bytes(16)
	return key


def decrypt_aes_key(aes_key_file, vault, key_name, key_version, client):
	try:
		with open(aes_key_file, 'r') as aes_key:
			key = base64.b64decode(aes_key.read())
			decrypted = client.decrypt(vault, key_name, key_version, 'RSA-OAEP', key)
	except IOError:
		print("Can't open key file!")
	return base64.b64decode(decrypted.result)

# Authenticate against AZ KeyVault
def az_key_vault_connection(az_client_id, az_secret, az_tenant_id):
	credentials = ServicePrincipalCredentials(
		client_id = az_client_id,
		secret = az_secret,
		tenant = az_tenant_id
	)
	client = KeyVaultClient(credentials)	
	return client

# Read Azure configuration file
def read_conf(azureConfFile):
  azure = {}
  try:
    with open(azureConfFile, 'r') as conf: 
      config = ConfigParser.ConfigParser()
      config.readfp(conf)
      for section_name in config.sections():
        for name, value in config.items(section_name):
          azure[name] = value
    print
  except IOError:
		print ("Can't read azure conf file!")
  return azure

# Create object to Azure RSA key
def az_get_rsa_key_info(az_connection, az_key_vault, az_key_name):
  rsa_key = {}
  versions = az_connection.get_key_versions(az_key_vault, az_key_name)
  for version in versions:
    az_key_version = version.kid.split('/')[-1]
  key = az_connection.get_key(az_key_vault, az_key_name, az_key_version)
  rsa_key['version'] = az_key_version
  rsa_key['key_bundle'] = key
  return rsa_key

# Encrypt AES key with Azure RSA key and store in Azure vault
def encrypt_and_store_aes_key(az_client, az_config, key_version, key):
  encrypted = az_client.encrypt(az_config['key_vault'], az_config['key_name'], key_version, 'RSA-OAEP', key)
  block_blob_service = BlockBlobService(account_name=az_config['account_name'], account_key=az_config['account_key'])
  block_blob_service.create_blob_from_text(
    az_config['container_name'],
    'aes_key-' + az_config['uuid'],
    base64.b64encode(encrypted.result)
  )

def retrieve_and_decrypt_aes_key(az_client, az_config, key_version, key_name):
  block_blob_service = BlockBlobService(account_name=az_config['account_name'], account_key=az_config['account_key'])
  aes_key = block_blob_service.get_blob_to_text(
    az_config['container_name'],
    key_name
  )
  decrypted = az_client.decrypt(az_config['key_vault'], az_config['key_name'], key_version, 'RSA-OAEP', base64.b64decode(aes_key.content))
  return decrypted.result

# Encrypt value using AES encryption 
# As AES required to store 3 fields: nonce, ciphertext and tag
# We will merge all fields into a single one using '-' as a delimiter
# The field delimiter will be # and base64 doesn't use '-' 
# nonce - ciphertext - tag - keyname
def encrypt(to_encrypt, key, uuid):
  encrypted=[]
  for value in to_encrypt: 
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(str(value)) 
    encrypted.append(base64.b64encode(cipher.nonce) + "-" + base64.b64encode(ciphertext) + "-" + base64.b64encode(tag) + "-" + base64.b64encode("aes_key-" + uuid))
  return encrypted

def decrypt(to_decrypt, key):
  decrypted=[] 
  for value in to_decrypt: 
    info = value.split('-')
    cipher = AES.new(base64.b64decode(key), AES.MODE_EAX, base64.b64decode(info[0]))
    data = cipher.decrypt_and_verify(base64.b64decode(info[1]), base64.b64decode(info[2]))
    decrypted.append(data)
  return decrypted

def main():
  arg = parsing_options()
  krb_client = Config(path=arg.hdfsConf).get_client()
  az_conf = read_conf(arg.azureConf)
  az_client = az_key_vault_connection(az_conf['azure_client_id'], az_conf['azure_client_secret'], az_conf['azure_tenant_id'])
  az_rsa_key = az_get_rsa_key_info(az_client, az_conf['key_vault'], az_conf['key_name'])
  column = list(itertools.chain.from_iterable(arg.column))
  with krb_client.read(arg.input) as inputFile:
    with krb_client.write(arg.output, overwrite=arg.overwrite) as outputFile:
      if arg.operation == 'encrypt':
        aes_key = generate_aes_key()
        az_conf['uuid'] = str(uuid.uuid4())
        encrypt_and_store_aes_key(az_client, az_conf, az_rsa_key['version'], base64.b64encode(aes_key))
        df = pd.read_csv(inputFile, sep=arg.delimiter, header=arg.header, dtype=str, chunksize=10000)
        num_chunk = 0
        for chunk in df:
          # Generate new column name and hash in place 
          new_column = []
          for i in column:
            new_column.append(str(i) + '_HASH')
          chunk[new_column] = chunk[column].apply(hash_value)
          # Encrypt in place 
          chunk[column] = chunk[column].apply(encrypt, args=(aes_key,az_conf['uuid']))
          if num_chunk == 0:
            chunk.to_csv(outputFile, sep=arg.delimiter, header=True, index=False)
            num_chunk += 1
          else:
            chunk.to_csv(outputFile, sep=arg.delimiter, header=False, index=False)
      else:
        df = pd.read_csv(inputFile, sep=arg.delimiter, header=arg.header, dtype=str, chunksize=1000)
        num_chunk = 0
        for chunk in df:
          if num_chunk == 0:
            # spliting only the first column - grabbing the 3rd field (key) and grabbing the value [0]
            key =  base64.b64decode(chunk[column[0]].str.split(pat='-', n=3, expand=True)[3][0])
            aes_key = retrieve_and_decrypt_aes_key(az_client, az_conf, az_rsa_key['version'], key)
          chunk[column]=chunk[column].apply(decrypt, args=(aes_key,))
          if num_chunk == 0:
            chunk.to_csv(outputFile, sep=arg.delimiter, header=True, index=False)
            num_chunk += 1
          else:
            chunk.to_csv(outputFile, sep=arg.delimiter, header=False, index=False)
      
	
if __name__ == "__main__":
  main()