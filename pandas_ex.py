#!/usr/bin/python
#
import pandas as pd 
import numpy
import hashlib




def hash_value(to_hash):
  hashed = hashlib.sha256(str(to_hash)).hexdigest()
  return hashed

def main():
	source='/home/orenault/Developments/col-encrypt/data/passwd'
	dest='/home/orenault/Developments/col-encrypt/data/pandas'
	col=0

	df=pd.read_csv(source,sep=":", header=None);#, names=["user","pwd","uid","gid","comment","home","shell"])
	cols = df.iloc[:,[0]]
	df.insert(col + 1, str(col) + '_enc', cols.applymap(hash_value))
	with open(dest + '1', 'w') as dest1:
		df.to_csv(dest1, sep=":", header=True, index=False)

	df.rename(columns={ col : str(col) + '_hash' }, inplace=True)
	#df.columns = numpy.arange(0,len(df.columns))


	#print df.apply(lambda row: hash_value(row[0]))

	with open(dest + '2', 'w') as dest2:
		cols.applymap(hash_value).to_csv(dest2, sep=":", header=True, index=False)
		#df.apply(lambda row: hash_value(row[0])).to_csv(dest)

	#print toto[toto.columns[0]]

if __name__ == "__main__":
  main()
