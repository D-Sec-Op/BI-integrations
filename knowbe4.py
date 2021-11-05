"""
Description: This program queries KnowBe4 for data related to simulated phishing campaign metrics, and pushes the data to PowerBI.
Date: July 2021
Author: Dan Schenk (koschenk@gmail.com)
"""
import requests
import json
from datetime import datetime as dt
from time import sleep

KB4_API_KEY = ""
auth = {'Authorization': 'Bearer ' + KB4_API_KEY}
pst_ids = []
start_dates = []
retry_count = 0

def campaign_data():  # Parses out data by campaign, combines targeted and non targeted, calls push_to_bi() after parsing
    print("campaign_data")
    short_url = ''
    long_url = ''
    push_data = {"Date": str(dt.now()),
                 "Campaign ID": None,
                 "Name": None,
                 "Start date": None,
                 "Delivered": None,
                 "Opened": None,
                 "Clicked": None,
                 "Reported": None,
                 "Phish prone percentage": None,
                 "Report percentage": None}  # Dict object to send to Power BI

    data = requests.get('https://us.api.knowbe4.com/v1/phishing/security_tests', headers=auth).json()

    # This while loop gets PST IDs of campaigns, combining targeted/general campaigns into nested lists
    tmp_list = []
    i = 0
    while i < 30:
        if "test" in data[i]["name"].lower():  # get rid of test campaigns
            i += 1
        elif data[i]['started_at'][0:7] == data[i + 1]['started_at'][0:7]:  # if two campaigns started same month/year
            tmp_list = [str(data[i]['pst_id']), str(data[i + 1]['pst_id'])]  # make them be a list
            pst_ids.append(tmp_list)  # add the list of 2 campaigns as one element in the pst_ids list
            start_dates.append(data[i]['started_at'])
            i += 2
        else:
            pst_ids.append(str(data[i]['pst_id']))
            start_dates.append(data[i]['started_at'])
            i += 1


    # This loop gets phishing simulation data, combines targeted/general monthly campaigns, and calls function to push data to BI
    i = 0
    while i < 30:
        push_data["Campaign ID"] = str(data[i]['campaign_id'])
        push_data["Name"] = str(data[i]['name']).split(' -')[0]
        push_data["Start date"] = data[i]['started_at']
        push_data["Delivered"] = data[i]['delivered_count']
        push_data["Opened"] = data[i]['opened_count']
        push_data["Clicked"] = data[i]['clicked_count']
        push_data["Reported"] = data[i]['reported_count']
        push_data["Phish prone percentage"] = round(data[i]['phish_prone_percentage'] * 100, 2)
        push_data["Report percentage"] = round((push_data["Reported"] / push_data["Delivered"]) * 100, 2)
        if push_data['Name'] == str(data[i + 1]['name']).split(' -')[0]:
            push_data["Delivered"] += data[i+1]['delivered_count']
            push_data["Opened"] += data[i+1]['opened_count']
            push_data["Clicked"] += data[i+1]['clicked_count']
            push_data["Reported"] += data[i+1]['reported_count']
            push_data["Phish prone percentage"] = round((push_data["Clicked"] / push_data["Delivered"]) * 100, 2)
            push_data["Report percentage"] = round((push_data["Reported"] / push_data["Delivered"]) * 100, 2)

            if i == 0:
                push_to_bi(short_url, push_data)
            i += 1

        if "test" in push_data["Name"].lower():  # filter out test campaigns
            i += 1
        else:
            if i == 0:
                push_to_bi(short_url, push_data)
            push_to_bi(long_url, push_data)
            i += 1


# get list of all campaign target groups
def list_groups():
    print('list_groups')
    bi_url = ''
    group_data = {'Date': str(dt.now())}

    resp = requests.get('https://us.api.knowbe4.com/v1/groups', headers=auth).json()
    for entry in resp:
        if entry['member_count'] != 0 and 'remedial' not in str(entry['name']).lower():
            group_data['ID'] = entry['id']
            group_data['Name'] = entry['name']
            group_data['Risk score'] = entry['current_risk_score']
            group_data['Members'] = entry['member_count']
            push_to_bi(bi_url, group_data)


# find everyone who clicks in campaigns
def clickers():
    print('clickers')
    clicked_new = []
    clicked_past = []
    repeat_clickers = []
    bi_click = ''
    bi_repeat = ''
    data = {'Date': str(dt.now())}

    for i in range(0, len(pst_ids)):
        if type(pst_ids[i]) == str: # pst IDs extracted earlier will be type str on single campaigns, or list for combined targeted campaigns, need to handle differently
            url = 'https://us.api.knowbe4.com/v1/phishing/security_tests/' + pst_ids[i] + '/recipients'
            for n in range(1, 4):
                sleep(0.5)
                resp = requests.get(url, headers=auth, params={'page': n, 'per_page': 500}).json()
                for entry in resp:
                    if entry['clicked_at'] is not None:
                        user = extract_offenders(str(entry['user']['id']))
                        if len(user) > 1:
                            data['Name'] = user[0]
                            data['Phish prone percentage'] = user[1]
                            data['Risk score'] = user[2]
                            data['VP'] = user[3].replace('VP ', '')
                            data['Start date'] = start_dates[i]
                            push_to_bi(bi_click, data)
                            if i == 0:
                                clicked_new.append(entry['user']['id'])
                            if i == 1:
                                clicked_past.append(entry['user']['id'])
        elif type(pst_ids[i]) == list: # pst IDs extracted earlier will be type str on single campaigns, or list for combined targeted campaigns, handle differently
            for p_id in pst_ids[i]:
                url = 'https://us.api.knowbe4.com/v1/phishing/security_tests/' + p_id + '/recipients'
                for n in range(1, 4):
                    sleep(0.5)
                    resp = requests.get(url, headers=auth, params={'page': n, 'per_page': 500}).json()
                    for entry in resp:
                        if entry['clicked_at'] is not None:
                            user = extract_offenders(str(entry['user']['id']))
                            if len(user) > 1:
                                data['Name'] = user[0]
                                data['Phish prone percentage'] = user[1]
                                data['Risk score'] = user[2]
                                data['VP'] = user[3].replace('VP ', '')
                                data['Start date'] = start_dates[i]
                                push_to_bi(bi_click, data)
                                if i == 0:
                                    clicked_new.append(entry['user']['id'])
                                if i == 1:
                                    clicked_past.append(entry['user']['id'])

    # compare the two most recent campaign click lists for overlap
    for user in clicked_new:
        if user in clicked_past:
            repeat_clickers.append(user)

    r_data = {'Date': str(dt.now())}
    for clicker in repeat_clickers:
        user = extract_offenders(str(clicker))
        if len(user) > 1:
            r_data['Name'] = user[0]
            r_data['Phish prone percentage'] = user[1]
            r_data['Risk score'] = user[2]
            r_data['VP'] = user[3].replace('VP ', '')
            push_to_bi(bi_repeat, r_data)



def extract_offenders(user_id):
    global retry_count
    retry_count = retry_count
    url = 'https://us.api.knowbe4.com/v1/users/' + user_id
    data = []

    sleep(0.5)
    resp = requests.get(url, headers=auth)
    if str(resp) != '<Response [200]>':
        if retry_count == 5:
            print("Failed to extract info for user ID:", user_id)
            data = []
            retry_count = 0
        else:
            retry_count += 1
            sleep(retry_count * 10)
            extract_offenders(user_id)
    else:
        resp = resp.json()
        data.append(resp['email'].split('@')[0].replace('.', ' ').title())
        data.append(resp['phish_prone_percentage'])
        data.append(resp['current_risk_score'])
        data.append(resp['organization'])
        retry_count = 0

    return data


def never_click():
    url = 'https://us.api.knowbe4.com/v1/users'
    bi_url = ''
    data = {'Date': str(dt.now())}

    print("never_click")
    for n in range(1, 5):
        sleep(0.5)
        resp = requests.get(url, headers=auth, params={'page': n, 'per_page': 500}).json()
        for entry in resp:
            if entry['phish_prone_percentage'] == 0:
                data['Name'] = entry['email'].split('@')[0].replace('.', ' ').title()
                if entry['organization'] is not None:
                    data['Department'] = entry['organization'].replace('VP ', '')
                else:
                    data['Department'] = None
                push_to_bi(bi_url, data)
                sleep(0.5)


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
    campaign_data()  # GET/parse data
    list_groups()
    clickers()
    never_click()


if __name__ == '__main__':
    main()