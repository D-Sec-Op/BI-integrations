"""
Description: This program queries SentinelOne for agent, app, and threat data and pushes to Power BI.
Date: August 2021
Author: Dan Schenk (koschenk@gmail.com)
"""
import requests
from datetime import datetime as dt
from datetime import timedelta as td
from time import sleep
import json

retry_count = 0
base = 'https://<TENANT>.sentinelone.net/web/api/v2.1/'
api_token = ''
token = {'Authorization': 'ApiToken ' + api_token}  # api-user

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


def alerts():
    resp = requests.get(base + 'cloud-detection/alerts', headers=token, verify=False).json()
    print(resp)

    for thing in resp['data']:
        print(thing)


def agents():
    print("agents")
    bi_url = ''
    data = {'Date': str(dt.now())}
    t_f = {True: 1, False: 0}
    resp = requests.get(base + 'agents', headers=token).json()
    for agent in resp['data']:
        data['activeThreats'] = agent['activeThreats']
        data['agentVersion'] = agent['agentVersion']
        data['appsVulnerabilityStatus'] = agent['appsVulnerabilityStatus'].replace('_', ' ')
        data['computerName'] = agent['computerName']
        data['coreCount'] = agent['coreCount']
        data['cpuCount'] = agent['cpuCount']
        data['cpuId'] = agent['cpuId']
        data['domain'] = agent['domain']
        data['externalIp '] = agent['externalIp']
        data['infected'] = agent['infected']
        data['inf'] = t_f[data['infected']]
        data['isActive'] = agent['isActive']
        data['isa'] = t_f[data['isActive']]
        data['isUpToDate'] = agent['isUpToDate']
        data['isu'] = t_f[data['isUpToDate']]
        if agent['locations'] is not None:
            data['location'] = agent['locations'][0]['name']
        else:
            data['location'] = None
        data['machineType'] = agent['machineType']
        data['mitigationMode'] = agent['mitigationMode']
        data['mitigationModeSuspicious'] = agent['mitigationModeSuspicious']
        data['modelName'] = agent['modelName'].replace('Corporation ', '')
        data['gatewayIp'] = agent['networkInterfaces'][0]['gatewayIp']
        data['IPs'] = str(agent['networkInterfaces'][0]['inet']).replace("'", "").replace("[", "").replace("]", "")
        data['networkStatus'] = agent['networkStatus']
        if data['networkStatus'] == 'connected':
            data['ns'] = 0
        else:
            data['ns'] = 1
        data['osName'] = agent['osName']
        data['osRevision'] = agent['osRevision']
        data['scanFinishedAt'] = agent['scanFinishedAt']
        data['scanStatus'] = agent['scanStatus']
        data['threatRebootRequired'] = agent['threatRebootRequired']
        data['trr'] = t_f[data['threatRebootRequired']]
        data['totalMemory'] = agent['totalMemory']
        data['updatedAt'] = agent['updatedAt']
        data['userActionsNeeded'] = str(agent['userActionsNeeded']).replace("'", "").replace("[", "").replace("]", "")
        push_to_bi(bi_url, data)


def apps():
    print("apps")
    data = {"Date": str(dt.now())}
    sev = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    bi_url = ''

    param = {"riskLevelsNin": "none", "limit": 100}
    resp = requests.get(base + 'installed-applications', headers=token, params=param).json()
    for app in resp['data']:
        data['Agent'] = app['agentComputerName']
        data['Domain'] = app['agentDomain']
        data['Application'] = app['name']
        data['Severity'] = app['riskLevel']
        data['sev'] = sev[data['Severity']]
        data['Version'] = app['version']
        push_to_bi(bi_url, data)


def threats():
    print("threats")
    bi_url = ''
    data = {"Date": str(dt.now())}
    con = {"malicious": 2, "suspicious": 1}
    res = {"resolved": 0, "unresolved": 1}

    param = {"createdAt__gte": str(dt.now() - td(days=90)), "limit": 100}
    resp = requests.get(base + 'threats', headers=token, params=param).json()
    for threat in resp['data']:
        data['Classification'] = threat['threatInfo']['classification']
        data['Confidence'] = threat['threatInfo']['confidenceLevel']
        if data['Confidence'] in con:
            data['con'] = con[data['Confidence']]
        else:
            data['con'] = 0
        data['Path'] = threat['threatInfo']['filePath']
        data['Identified'] = threat['threatInfo']['identifiedAt']
        data['Incident status'] = threat['threatInfo']['incidentStatus']
        data['res'] = res[data['Incident status']]
        data['Initiated by'] = threat['threatInfo']['initiatedBy']
        data['Malicious args'] = threat['threatInfo']['maliciousProcessArguments']
        data['Mitigation status'] = threat['threatInfo']['mitigationStatus'].replace('_', ' ')
        data['mit'] = len(data['Mitigation status'])
        data['Name'] = threat['threatInfo']['threatName']
        data['Agent'] = threat['agentRealtimeInfo']['agentComputerName']
        push_to_bi(bi_url, data)


def main():
    # alerts()
    agents()
    apps()
    threats()


if __name__ == '__main__':
    main()
