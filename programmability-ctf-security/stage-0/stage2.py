import requests
import json
import sys
import datetime
from pathlib import Path
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from pprint import pprint
from urllib.parse import quote
from urllib.parse import urlparse


here = Path(__file__).parent.absolute()
repository_root = (here / ".." ).resolve()
sys.path.insert(0, str(repository_root))

import env

client_id=env.AMP.get("client_id")
api_key=env.AMP.get("api_key")
host=env.AMP.get("host")
th_api_key=env.THREATGRID.get("api_key")
th_host=env.THREATGRID.get("host")

#GET Events
headers = {'Content-Type': 'application/json'}
url=f"https://{client_id}:{api_key}@{host}/v1/events"
response = requests.get(url, headers=headers)
#pprint(response.json())

for item in response.json()['data']:
    if item['computer']['hostname']=="Demo_AMP_Threat_Audit":   #extract connector_guid from desired host
        con_guid=item['computer']['connector_guid']

print("Connector_guid for Demo_AMP_Threat_Audit is : ")
print(con_guid)
print("\n")
url=f"https://{client_id}:{api_key}@{host}/v1/events?connector_guid[]={con_guid}" #get all events for our desired host
response = requests.get(url, headers=headers)

#pprint(response.json())
#check for Executed malware event type
t_hash=[]
threat_names=[]
for item in response.json()['data']:
    if item['event_type']=="Executed malware": 
        print("Malware detected, " +item['file']['file_name']+ ", proceeding with host isolation...\n")
        t_hash.append(item['file']['identity']['sha256'])  #get the sha256 hashes, list them
        threat_names.append(item['file']['file_name']) #save name
#check for isolation
url=f"https://{client_id}:{api_key}@{host}/v1/computers/{con_guid}/isolation"
response = requests.get(url, headers=headers)
#pprint(response.json())
if response.json()['data']['status']=="isolated":
    print("Host has already been isolated by "+ response.json()['data']['isolated_by'])
else:
    response = requests.put(url, headers=headers)
    print("You have isolated the host")

####ThreatGrid - sha256 hash
k=0
#with open('reportdomains.txt', 'w') as file: #create/open file to write report
my_file=open('reportdomains.txt', 'w')
for i in t_hash:   
    url=f"https://{th_host}/api/v2/search/submissions?state=succ&q={i}&api_key={th_api_key}"
    response = requests.get(url) #check hash
    if response.json()['data']['current_item_count']!=0: #check if file hash in threatgrid
        url=f"https://{th_host}/api/v2/samples/feeds/domains?sample={response.json()['data']['items'][0]['item']['sample']}&api_key={th_api_key}"
        response_dom = requests.get(url) #check for domains with that threat
        my_file.write("Malware named " +threat_names[k]+ " found on domain " + response_dom.json()['data']['items'][0]['domain'] +"\n") #review response structure...
k+=1

my_file.close() #close file

#OK

