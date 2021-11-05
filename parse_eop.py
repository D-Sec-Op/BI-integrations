import requests
import json
from datetime import datetime as dt
from time import sleep

retry_count = 0
bi_url = ''
ts = str(dt.now())

def parse_report():
        data = {'Today': ts}
        with open('eop.txt', 'r') as report:
                for line in report:
                        info = line.split(':')
                        if len(info) == 4:
                                data['Date'] = info[1][1:11]
                        if len(info) == 2:
                                if info[0][:9] == 'EventType':
                                        data['Type'] = info[1].replace(' ', '').replace('\n', '')
                                elif info[0][:9] == 'Direction':
                                        data['Direction'] = info[1].replace(' ', '').replace('\n', '')
                                elif info[0][:12] == 'MessageCount':
                                        data['Count'] = info[1].replace(' ', '').replace('\n', '')
                        if len(info) == 1 and len(data) > 1:
                                push_to_bi(bi_url, data)
                                data = {'Today': ts}


def push_to_bi(bi_url, data):
        global retry_count
        retry_count = retry_count
        j_data = [data]  # Format data for transmission to Power Bi
        r = requests.post(bi_url, json.dumps(j_data))  # Push data to Power BI
        if str(r) != '<Response [200]>':
                if retry_count == 5:
                        print(r, r.text)
                        print("This failed:", data)
                        retry_count = 0
                elif str(r) == '<Response [429]>':
                        retry_count += 1
                        sleep(retry_count * 30)
                        push_to_bi(bi_url, data)
                else:
                        retry_count += 1
                        sleep(retry_count * 4)
                        push_to_bi(bi_url, data)
        else:
                retry_count = 0


def main():
        parse_report()


if __name__ == '__main__':
        main()