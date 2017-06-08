#!/usr/bin/python

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

public_key='/home/orenault/Developments/column-crypt/id_rsa.pub'
private_key='/home/orenault/Developments/column-crypt/id_rsa'

message = b'To be encrypted'
key = RSA.importKey(open(public_key).read())
cipher = PKCS1_OAEP.new(key)

ciphertext = cipher.encrypt(message)
print "test %b", ciphertext

key = RSA.importKey(open(private_key).read())
cipher = PKCS1_OAEP.new(key)
message = cipher.decrypt(ciphertext)

print message