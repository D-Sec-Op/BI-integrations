"""
Description: This program pulls in 30 days of detected threats from Panorama and pushes to Power BI.
Date: June/July 2021
Author: Dan Schenk (koschenk@gmail.com)
"""
import xml.etree.ElementTree as ET
import requests
import json
import time
import datetime

data = {"Date": str(datetime.datetime.now())}
retry_count = 0

key = ''
url = 'https://<ON_prem_panorama_url>//api/?key=' + key
report = ''
head = '&type=report&async=yes&reporttype=custom&reportname=' + report
bi_url = ''


def get_data(): # Send request for report to be made of top threats to the iDMZ for the past 30 days
    r = requests.get(url + head)
    root = ET.fromstring(r.content)
    job = root[0][1].text                       # Extract job ID of requested report
    time.sleep(90)                              # Wait before sending request for results of job, else will fail

    head2 = "&type=report&action=get&job-id="  + job
    resp = requests.get(url+head2)              # Request results of report requested above
    root = ET.fromstring(resp.content)

    for child in root[0][1]:    # each "child" here is a detected threat
        for entry in child:             # each entry is an attribute of the threat (ID, Category, action taken by Pan etc.)
            data[entry.tag] = entry.text # Assign appropriate value to each attribute in dict object to send to BI
        push_to_bi(bi_url, data)                                # Push each threat individually to BI


def push_to_bi(bi_url, data):
    global retry_count
    retry_count = retry_count # need global retry count for recursion
    j_data = [data]  # Format data for transmission to Power Bi
    r = requests.post(bi_url, json.dumps(j_data))  # Push data to Power BI
    if str(r) != '<Response [200]>': # if push not successful
        if retry_count == 5: # try five times, then move on
            print(r, r.text)
            print("This failed:", data)
            retry_count = 0
        elif str(r) == '<Response [429]>': # 429 is rate limiting, sleep long to cool down
            retry_count +=1
            sleep(retry_count * 30)
            push_to_bi(bi_url, data)
        else:           # if failed but not 429 dont sleep as long, probably just 500 internal server error
            retry_count += 1
            sleep(retry_count * 4)
            push_to_bi(bi_url, data)
    else:
        retry_count = 0


def main():
    get_data()


if __name__ == '__main__':
    main()