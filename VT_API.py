# VirusTotal_API Exection program

import sys
import json
import urllib
import urllib2
import hashlib

# sys.argv[1] -> TargetFile(Absolute pass)
# sys.argv[2] -> Result_dir
# sys.argv[3] -> TargetFile_name
# sys.argv[4] -> APIkey

# Target checksum

api_key = sys.argv[4]

argvs = sys.argv
argc = len(argvs)


if (argc <= 2):
        print 'Usage: python Targetfile(Absolute pass) Result_dir Targetfilename'
        sys.exit(1)

TargetFile = sys.argv[1]

with open(TargetFile, 'rb') as f:
    hash = hashlib.sha256(f.read()).hexdigest()

# API
Result_dir = sys.argv[2]
TargetFile = sys.argv[3]

url = "https://www.virustotal.com/vtapi/v2/file/report"
parameters = {"resource": hash, "apikey": api_key}

data = urllib.urlencode(parameters)
req = urllib2.Request(url, data)
response = urllib2.urlopen(req)
json = response.read()

with open(Result_dir + str(TargetFile) + ".json", "w") as file:
    file.write(json)

