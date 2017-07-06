#!/usr/bin/env python
# encoding: utf-8

from hdfs import Config
# Requires avro
from hdfs.ext.dataframe import read_dataframe, write_dataframe
from hdfs.ext.kerberos import KerberosClient
import pandas as pd

def generate_conf():
  print toto

def main():
  client = Config(path='/tmp/hdfscli.conf').get_client()
  print client

if __name__ == "__main__":
  main()
