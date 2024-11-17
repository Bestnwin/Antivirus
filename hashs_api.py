#!/usr/bin/env python3

# This module retrieves SHA256, SHA1, and MD5 hashes from VirusTotal and places each into a separate text file,
# and also creates a CSV file with additional information for each finding

import os
import requests
import time

url = 'https://www.virustotal.com/api/v3/files/'
# You'll need to create an environment variable VT_API_KEY with your API key as the value
headers = {'x-apikey': os.environ['ur api']}
counter = 0
linecounter = 0

# Create a subdirectory in the IOCs directory
iocname = input('Enter a directory name for the IOCs: ')
os.makedirs('./IOCs/{}/'.format(iocname), mode=0o644, exist_ok=True)

# Open the file containing IOCs to search in VirusTotal
with open('HashesForVT.txt', 'r') as f:
    for line in f:
        searchhash = line
        linecounter += 1
        r = requests.get(url + searchhash, headers=headers)

        # If file exists in VT, retrieve the hashes
        if r.status_code == 200:
            counter += 1
            print('Retrieving {0} of {1} hashes...'.format(counter, linecounter))
            sha256hash = r.json()['data']['attributes']['sha256']
            sha1hash = r.json()['data']['attributes']['sha1']
            md5hash = r.json()['data']['attributes']['md5']
            filetype = r.json()['data']['attributes']['type_description']
            filesize = str(r.json()['data']['attributes']['size'])
            names = str(r.json()['data']['attributes']['names'])
            malicious = r.json()['data']['attributes']['last_analysis_stats']['malicious']
            undetected = r.json()['data']['attributes']['last_analysis_stats']['undetected']
            detections = str(malicious) + '/' + str(malicious + undetected)

            # Create text files for SHA256, SHA1, and MD5 hashes
            # and a CSV file with additional information
            with open('./IOCs/{0}/{0}-SHA256hashes.txt'.format(iocname), 'a') as w1:
                w1.write(sha256hash + '\n')
            with open('./IOCs/{0}/{0}-SHA1hashes.txt'.format(iocname), 'a') as w2:
                w2.write(sha1hash + '\n')
            with open('./IOCs/{0}/{0}-MD5hashes.txt'.format(iocname), 'a') as w3:
                w3.write(md5hash + '\n')
            with open('./IOCs/{0}/{0}-combined.csv'.format(iocname), 'a') as csvfile:
                csvfile.write(sha256hash + ',' + sha1hash + ',' + md5hash + ',' + detections + ',' + filetype + ',' + filesize + ',' + names + '\n')
            
            # VirusTotal's Public API is limited to four requests/minute, so we'll pause for 15 seconds after a request is complete
            # If you have a Premium API account, you may comment out this timer or remove it
            time.sleep(15)

        else:
            print('Line {} - '.format(linecounter) + searchhash.strip() + ' not found in VirusTotal')
