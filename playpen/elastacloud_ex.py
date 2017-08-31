#!/usr/bin/env python
import json
import requests
from azure.common.credentials import *
from azure.keyvault import KeyVaultClient, KeyVaultAuthentication
import base64
 
AUTHORITY_HOST = ""
TENANT_ID      = ""
CLIENT_ID      = ""
CLIENT_SECRET  = ""
VAULT          = ''
KEY_NAME       = ''
 
data = { "grant_type" : "client_credentials",
        "client_id" : CLIENT_ID,
        "client_secret" : CLIENT_SECRET,
        "resource" : "https://vault.azure.net"
    }
 
credentials = ServicePrincipalCredentials(client_id=CLIENT_ID,
                                                  secret=CLIENT_SECRET,
                                                  tenant=TENANT_ID)
 
client = KeyVaultClient(credentials)
keybundle = client.create_key('https://eckeys.vault.azure.net', KEY_NAME, 'RSA')
# show the key_id
key = keybundle.key
# get the key
key_version = key.key.kid.split('/')[-1]
get_key = client.get_key('https://eckeys.vault.azure.net', KEY_NAME, key_version)
 
# do some encryption here ...
encoded = base64.b64encode(b'hello from Elastacloud')
encrypted = client.encrypt('https://eckeys.vault.azure.net', KEY_NAME, key_version, 'RSA-OAEP', encoded)
# decrypt here
decrypted = client.decrypt('https://eckeys.vault.azure.net', KEY_NAME, key_version, 'RSA-OAEP', encrypted.result)
decoded = base64.b64decode(decrypted.result)