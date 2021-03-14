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

inv_url = env.UMBRELLA.get("inv_url")
inv_token = env.UMBRELLA.get("inv_token")
en_key = env.UMBRELLA.get("en_key")
#Use a domain of your choice
domain = input("Please enter a domain:\n") #enter whatever domain

#Construct the API request to the Umbrella Investigate API to query for the status of the domain
url = f"{inv_url}/domains/categorization/{domain}?showLabels"
headers = {"Authorization": f'Bearer {inv_token}'}
response = requests.get(url, headers=headers)


response.raise_for_status()



#Make sure the right data in the correct format is chosen, you can use print statements to debug your code
domain_status = response.json()[domain]["status"]

url = f"{inv_url}/pdns/domain/{domain}?limit=2"  #limit to 2 records
headers = {"Authorization": f'Bearer {inv_token}'}
responsehis = requests.get(url, headers=headers)


##print report 


print("\n")
print("Info for "+domain+":")
print("\n")
if domain_status == 1:
    print(f"The domain {domain} is found CLEAN")
elif domain_status == -1:
    print(f"The domain {domain} is found MALICIOUS")
elif domain_status == 0:
    print(f"The domain {domain} is found UNDEFINED")
print("\n")
categories=response.json()[domain]['content_categories']
print("Content categories:",categories)
print("\n")
print("****Historical data for "+domain+":\n")
print("Total number of records: "+str(responsehis.json()['pageInfo']['totalNumRecords']))
print("\n")
print("Total number of malicious domains: "+str(responsehis.json()['recordInfo']['totalMaliciousDomain']))
print("\n")
print("****Record info:\n")
for record in responsehis.json()['records']:
    print("Name: "+record['name'])
    print("\n")
    print("RR: "+record['rr'])
    print("\n")
    print("Content categories: ",record['contentCategories'])
    print("\n")
    print("First seen: "+record['firstSeenISO'])
    print("\n")
    print("Last seen: "+record['lastSeenISO'])
    print("\n-----------------------")

date=datetime.datetime.now().replace(microsecond=0).isoformat()
date+=".0Z" # correct datetime format

#Umbrella enforcement API
if domain_status == -1 : 
    url= f"https://s-platform.api.opendns.com/1.0/events?customerKey={en_key}"
    headers = {'Content-Type': 'application/json'}
    payload={'alertTime': date,
    'deviceId': 'ba6a59f4-e692-4724-ba36-c28132c761de',
    'deviceVersion': '13.7a',
    'dstDomain': domain,
    'dstUrl': domain,
    'eventTime': date,
    'protocolVersion': '1.0a',
    'providerName': 'Security Platform'}
    payload=json.dumps(payload)
    responseenf = requests.post(url, headers=headers, data=payload)
    print(responseenf.json())
    
    
    print("Domain "+domain+ " added to block list (Malicious)")


#datetime.datetime.now().isoformat()