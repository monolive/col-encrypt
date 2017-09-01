#!/usr/bin/env python

import base64

inputFile = open('/home/orenault/Developments/CAVM/col-encrypt/data/test')
outputFile = open('../data/result', 'w')

content = inputFile.read()
b64content = content.encode('base64')

print b64content

b64content = base64.b64encode(content)
print b64content

content = base64.b64decode(b64content)
print content


outputFile.write(b64content)

inputFile.close()
outputFile.close()