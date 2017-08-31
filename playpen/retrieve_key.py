#!/usr/bin/env python
# encoding: utf8
# Retrieve key from Azure KMS

import adal
from ConfigParser import SafeConfigParser
from azure.keyvault import KeyVaultClient, KeyVaultId
from azure.mgmt.keyvault import KeyVaultManagementClient, operations
from azure.common.credentials import ServicePrincipalCredentials


parser = SafeConfigParser()
parser.read('/home/orenault/Developments/col-encrypt/conf/azure-credentials.txt')



credentials = ServicePrincipalCredentials(
    client_id = parser.get('Azure', 'AZURE_CLIENT_ID'),
    secret = parser.get('Azure', 'AZURE_CLIENT_SECRET'),
    tenant = parser.get('Azure', 'AZURE_TENANT_ID')
)

KEY_VAULT_URI = 'https://oren-test.vault.azure.net'
client = KeyVaultManagementClient(credentials, parser.get('Azure', 'AZURE_SUBSCRIPTION'), KEY_VAULT_URI)

#client = KeyVaultClient(credentials)

print "============= authenticated ==========="
print operations.VaultsOperations('list',)




# Create a key

print client


#key_bundle = client.create_key(KEY_VAULT_URI, 'FirstKey', 'RSA')
#key_id = KeyVaultId.parse_key_id(key_bundle.key.kid)

# Update a key without version
#client.update_key(key_id.vault, key_id.name, key_id.version_none, key_attributes={'enabled': False})

# Update a key with version
#client.update_key(key_id.vault, key_id.name, key_id.version, key_attributes={'enabled': False})

# Print a list of versions for a key
#versions = client.get_key_versions(KEY_VAULT_URI, 'FirstKey')
#for version in versions:
#    print(version.kid)  # https://myvault.vault.azure.net/keys/FirstKey/000102030405060708090a0b0c0d0e0f

# Read a key without version
#client.get_key(key_id.vault, key_id.name, key_id.version_none)#

# Read a key with version
#client.get_key(key_id.vault, key_id.name, key_id.version)

# Delete a key
#client.delete_key(KEY_VAULT_URI, 'FirstKey')


# Create a secret
#secret_bundle = client.set_secret(KEY_VAULT_URI, 'FirstSecret', 'Hush, that is secret!!')
#secret_id = KeyVaultId.parse_secret_id(secret_bundle.id)

#print secret_id.version

# Update a secret without version
#client.update_secret(secret_id.vault, secret_id.name, secret_id.version_none, secret_attributes={'enabled': False})

# Update a secret with version
#client.update_key(secret_id.vault, secret_id.name, secret_id.version, secret_attributes={'enabled': False})

# Print a list of versions for a secret
#versions = client.get_secret_versions(KEY_VAULT_URI, 'FirstSecret')
#for version in versions:
#    print(version.id)  # https://myvault.vault.azure.net/secrets/FirstSecret/000102030405060708090a0b0c0d0e0f

# Read a secret without version
#client.get_secret(secret_id.vault, secret_id.name, secret_id.version_none)

# Read a secret with version
#client.get_secret(secret_id.vault, secret_id.name, secret_id.version)

# Delete a secret

print "done"