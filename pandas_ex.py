#!/usr/bin/python
#
import pandas as pd 


source='/home/orenault/Developments/col-encrypt/data/passwd'
dest='/home/orenault/Developments/col-encrypt/data/pandas'

df=pd.read_csv(source,delimiter=":");#, names=["user","pwd","uid","gid","comment","home","shell"])

print len(df.columns)

print df.iloc[:,:2]

#print toto[toto.columns[0]]