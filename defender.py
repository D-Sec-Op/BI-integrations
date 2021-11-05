"""
Description: This program pulls in data from MS Defender and pushes to Power BI
Date: June/July 2021
Author: Dan Schenk (koschenk@gmail.com)
"""
import requests
import json
from datetime import datetime as dt
import urllib.request
import urllib.parse

retry_count = 0


def get_token(): # Obtains auth token to make API calls to defender
    print("get_token")
    appId = ''
    appSecret = ''
	tenant_id = ''
	
    # Azure Active Directory token endpoint.
    url = "https://login.microsoftonline.com/" + tenant_id + "/oauth2/v2.0/token"
    body = {
        'client_id': appId,
        'client_secret': appSecret,
        'grant_type': 'client_credentials',
        'scope': 'https://api.securitycenter.microsoft.com/.default'
    }

    # authenticate and obtain AAD Token for future calls
    data = urllib.parse.urlencode(body).encode("utf-8")  # encodes the data into a 'x-www-form-urlencoded' type
    req = urllib.request.Request(url, data)

    response = urllib.request.urlopen(req)

    jsonResponse = json.loads(response.read().decode())
    # print(jsonResponse)
    # Grab the token from the response then store it in the headers dict.
    aadToken = jsonResponse["access_token"]

    if len(aadToken) > 0:
        return aadToken
    else:
        print("Authentication failed. Exiting program...")
        exit(-1)


def get_vulns(token):   # gets top 10 vulnerabilities
    print("get_vulns")
    auth = {'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': 'Bearer ' + token} # formatted header for making requests
    url = 'https://api.securitycenter.microsoft.com/api/Vulnerabilities?$top=10' # edit the top=n for more/less results
    bi_url = ''
    data = {'Date': str(dt.now())}
    resp = requests.get(url, headers=auth).json()
    # print(resp)
    for entry in resp['value']:         # parsing out relevant data
        data['Name'] = entry['name']
        data['Description'] = entry['description'].replace('To view more details about this vulnerability please visit the vendor website.', '') # get rid of junk string
        data['Severity'] = entry['severity']
        if data['Severity'] == 'Low':
            data['sev'] = 1
        elif data['Severity'] == 'Medium':
            data['sev'] = 2
        elif data['Severity'] == 'High':
            data['sev'] = 3
        elif data['Severity'] == 'Critical':
            data['sev'] = 4
        else:
            data['sev'] = 0
        data['CVSS'] = entry['cvssV3']
        data['Exposed machines'] = entry['exposedMachines']
        # print(data)
        push_to_bi(bi_url, data) # send each vulnerability to BI individually after parsing


def get_alerts(token):  # gets top ten alerts
    print("get_alerts")
    auth = {'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': 'Bearer ' + token}
    url = 'https://api.securitycenter.microsoft.com/api/alerts?$top=10' # edit top=n fore more/less results
    bi_url = ''
    data = {'Date': str(dt.now())}
    resp = requests.get(url, headers=auth).json()
    # print(resp)
    for alert in resp['value']: # parse out and format relevant data for each alert
        data['ID'] = alert['id']
        data['Severity'] = alert['severity']
        if data['Severity'] == 'Low':
            data['sev'] = 1
        elif data['Severity'] == 'Medium':
            data['sev'] = 2
        elif data['Severity'] == 'High':
            data['sev'] = 3
        elif data['Severity'] == 'Critical':
            data['sev'] = 4
        else:
            data['sev'] = 0
        data['Status'] = alert['status']
        if alert['assignedTo'] is not None:
            data['Assigned to'] = alert['assignedTo'].split('@')[0].replace('.', ' ')
        else:
            data['Assigned to'] = None
        data['Title'] = alert['title']
        data['Classification'] = alert['classification']
        data['Investigation state'] = alert['investigationState']
        data['Category'] = alert['category']
        data['First event'] = alert['firstEventTime']
        data['Last event'] = alert['lastEventTime']
        data['Description'] = alert['description']
        data['Machine name'] = alert['computerDnsName']

        if type(alert['relatedUser']) == dict:
            data['User'] = alert['relatedUser']['userName']
        else:
            data['User'] = None
        if len(alert['mitreTechniques']) > 0:
            data['Mitre technique'] = str(alert['mitreTechniques']).replace("'", "").replace("[", "").replace("]", "")
        else:
            data['Mitre technique'] = None
        # print(data)
        push_to_bi(bi_url, data) # send parsed data to BI for each alert


def get_score(token):   # gets secure score related data
    print("get_score")
    auth = {'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': 'Bearer ' + token}

    # uncomment and use below block of text to separate score by group *** Would need to change/rebuild the BI endpoint***
    # url = 'https://api.securitycenter.microsoft.com/api/exposureScore/ByMachineGroups'
    # bi_url = ''
    # data = {'Date': str(dt.now())}
    # resp = requests.get(url, headers=auth).json()
    # # print(resp)
    # for entry in resp['value']:
    #     data['Score'] = entry['score']
    #     data['Group'] = entry['rbacGroupName']
    #     data['Group ID'] = entry['rbacGroupId']
    #     print(data)

    bi_url2 = ''
    data2 = {'Date': str(dt.now())}
    url2 = 'https://api.securitycenter.microsoft.com/api/configurationScore'
    resp2 = requests.get(url2, headers=auth).json()
    data2['Device Secure Score'] = resp2['score']

    url3 = 'https://api.securitycenter.microsoft.com/api/exposureScore'
    resp3 = requests.get(url3, headers=auth).json()
    data2['Exposure Score'] = resp3['score']
    push_to_bi(bi_url2, data2) # push the two scores to BI together


def get_recommend(token): # Gets top 25 security recommendations from defender
    print("get_recommend")
    auth = {'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': 'Bearer ' + token}
    url = 'https://api.securitycenter.microsoft.com/api/recommendations?$top=25'
    bi_url = ''
    data = {'Date': str(dt.now())}

    resp = requests.get(url, headers=auth).json()

    for entry in resp['value']:
        if entry['status'] == 'Active': # Do not show recommendations for which exceptions exist
            data['Affected Product'] = entry['relatedComponent']
            data['Recommendation'] = entry['recommendationName']
            data['Vendor'] = entry['vendor']
            data['Category'] = entry['recommendationCategory']
            data['Sub-Category'] = entry['subCategory']
            data['Severity'] = entry['severityScore']
            data['Public Exploit'] = entry['publicExploit']
            data['exp'] = int(entry['publicExploit'])
            data['Active Alert'] = entry['activeAlert']
            data['act'] = int(entry['activeAlert'])
            data['Remediation'] = entry['remediationType']
            data['Config Score Impact'] = entry['configScoreImpact']
            data['Exposure Score Impact'] = entry['exposureImpact']
            data['Total Machines'] = entry['totalMachineCount']
            data['Exposed Machines'] = entry['exposedMachinesCount']
            push_to_bi(bi_url, data)


def get_remediations(token): # gets active remediation activities
    print("get_remediations")
    auth = {'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': 'Bearer ' + token}
    url = 'https://api.securitycenter.microsoft.com/api/remediationtasks'
    bi_url = '
    data = {'Date': str(dt.now())}
    scale = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
    resp = requests.get(url, headers=auth).json()

    for entry in resp['value']:
        data['Title'] = entry['title']
        data['Requester'] = entry['requesterEmail'].split('@')[0].replace('.', ' ').title()
        data['Component'] = entry['relatedComponent']
        data['Target Devices'] = entry['targetDevices']
        data['RBAC Groups'] = str(entry['rbacGroupNames']).replace("'", "").replace("[", "").replace("]", "")
        data['Fixed Devices'] = entry['fixedDevices']
        data['Notes'] = entry['requesterNotes']
        data['Due'] = entry['dueOn']
        if data['Due'] < data['Date']:
            data['od'] = 1
        else:
            data['od'] = 0
        data['Priority'] = entry['priority']
        data['p_scale'] = scale[entry['priority']]
        push_to_bi(bi_url, data)


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
    token = get_token()
    get_vulns(token)
    get_alerts(token)
    get_score(token)
    get_recommend(token)
    get_remediations(token)


if __name__ == '__main__':
    main()