#!/usr/bin/env python
# encoding: utf8
# Retrieve key from Azure KMS

import adal
from azure.keyvault import KeyVaultClient,KeyVaultId
from azure.common.credentials import ServicePrincipalCredentials

credentials = ServicePrincipalCredentials(
    client_id = '18b9b04f-42b3-46e2-8b70-0882fe1ee196',
    secret = '89e09b9c-42bd-4ab0-b13c-01d9a0141ad8',
    tenant = 'def64197-6c74-4d7d-9916-85a01b2fd9b6'
)

client = KeyVaultClient(
  credentials
)

KEY_VAULT_URI = 'https://oren-test.vault.azure.net'
# Create a key
key_bundle = client.create_key(KEY_VAULT_URI, 'FirstKey', 'RSA')
key_id = KeyVaultId.parse_key_id(key_bundle.key.kid)

client.get_key(key_id.vault, key_id.name, key_id.version_none)
print client


