#!/usr/bin/env python
# encoding: utf-8

from hdfs import Config

# Requires avro
from hdfs.ext.dataframe import read_dataframe, write_dataframe
from hdfs.ext.kerberos import KerberosClient
import pandas as pd

hdfscliconf = '/home/orenault/Developments/col-encrypt/conf/hdfscli.cfg'

def generate_conf():
  print toto

def main():
  client = Config(path=hdfscliconf).get_client()
  with client.read('/user/orenault/passwd') as input:
    #print input.read()
    df=pd.read_csv(input, sep=':', header=None)
    cols = df.iloc[:,0]

    client.write('/user/orenault/data.avro', cols.to_csv(sep=":", header=True, index=False), overwrite=True)

if __name__ == "__main__":
  main()
