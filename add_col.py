#!/usr/bin/python

import hashlib
import csv


def main():
  file = "/home/orenault/Developments/column-crypt/passwd"
  with open(file + '.enc', 'w') as fresults, open(file) as fsource:
    reader = csv.reader(fsource, delimiter=":")
    writer = csv.writer(fresults, delimiter=":")
    headers = reader.next()
    print headers[2]
    headers.append(headers[2] + "_ENC")
    writer.writerow(headers)
    fresults.close()
    fsource.close()

if __name__ == "__main__":
    main()
