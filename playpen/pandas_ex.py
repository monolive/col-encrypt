#!/usr/bin/python
#
import pandas as pd 
import numpy
import hashlib
import M2Crypto
import base64

privateRSAkey = '/home/orenault/Developments/col-encrypt/keys/private_key.pem'

def decrypt(to_decrypt):
	privateRSA = M2Crypto.RSA.load_key(privateRSAkey)
	try:
		PlainText = privateRSA.private_decrypt(to_decrypt.decode('base64'), M2Crypto.RSA.pkcs1_oaep_padding)
	except:
		print "Error: wrong key?"
		PlainText = ""
	return PlainText

def decrypt2(to_decrypt, privateRSA):
	try:
		PlainText = privateRSA.private_decrypt(to_decrypt.item().decode('base64'), M2Crypto.RSA.pkcs1_oaep_padding)
	except:
		print "Error: wrong key?"
		PlainText = ""
	return PlainText

def hash_value(to_hash):
  hashed = hashlib.sha256(str(to_hash)).hexdigest()
  return hashed

def main():
	source='/home/orenault/Developments/col-encrypt/data/passwd.header.encrypted'
	dest='/home/orenault/Developments/col-encrypt/data/pandas'
	col=[7]
	privateRSA = M2Crypto.RSA.load_key(privateRSAkey)
	df=pd.read_csv(source,sep=":", header=1)
	cols = df.iloc[:,col]
	

# Decrypt value and replace value
	with open(dest + '6', 'w') as dest6:
		# Do not forget the comma behind the privateRSA
		# the correct python grammer for a singleton tuple is (1,) not (1), which is just an
		# expr wth the value 1. 
		df[col]=cols.apply(decrypt2, args = (privateRSA,) , axis = 1)
		df.to_csv(dest6, sep=":", header=0, index=False)

# Hash value and replace original
	with open(dest + '3', 'w') as dest3:
		df[col] = cols.applymap(hash_value)
		df.to_csv(dest3, sep=":", header=0, index=False)
	

# Apply hash but not included in file
#	with open(dest + '2', 'w') as dest2:
#		cols.applymap(hash_value).to_csv(dest2, sep=":", header=True, index=False)
		


# Decrypt but not passing the key arg
#	with open(dest + '4', 'w') as dest4:		
#		cols.applymap(decrypt).to_csv(dest4, sep=":", header=0, index=False)
	
if __name__ == "__main__":
  main()
