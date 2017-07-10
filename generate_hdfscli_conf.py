#!/usr/bin/env python
# encoding: utf-8

# xml parser
import xml.etree.ElementTree as ET
# regex: use for stripping xml tag
import re
# get username 
import os

def main():
  coresite = '/home/orenault/Developments/col-encrypt/conf/core-site.xml'
  hdfssite = '/home/orenault/Developments/col-encrypt/conf/hdfs-site.xml'
  hdfscliConf = '/home/orenault/Developments/col-encrypt/conf/hdfscli.cfg'

  # Read core-site.xml
  with open(coresite, 'r') as coresite:  
    config_tree = ET.parse(coresite)
    for properties in config_tree.iterfind("property"):
      element = ET.tostring(properties.find("name"))
      value = ET.tostring(properties.find("value"))
      if 'hadoop.security.authentication' in element:
        print re.sub('<[^>]*>', '', value)
        security = re.sub('<[^>]*>', '', value).rstrip()
        break

  with open(hdfssite, 'r') as hdfssite:  
    config_tree = ET.parse(hdfssite)
    for properties in config_tree.iterfind("property"):
      element = ET.tostring(properties.find("name"))
      value = ET.tostring(properties.find("value"))
      if 'dfs.namenode.http-address' in element:
        print re.sub('<[^>]*>', '', value)
        namenode = re.sub('<[^>]*>', '', value).rstrip()
        break


  with open(hdfscliConf, 'w') as hdfscli:
    hdfscli.write('[global]\n')
    hdfscli.write('default.alias = hadoop\n\n')
    hdfscli.write('[hadoop.alias]\n')
    hdfscli.write('url = http://' + namenode + '\n')
    hdfscli.write('user = ' + os.getlogin() + '\n')


    
  if security == 'kerberos':
    print Youpi

if __name__ == "__main__":
  main()
