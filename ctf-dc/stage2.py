import requests
import json
import csv
from pprint import pprint

from utils.auth import IntersightAuth, get_authenticated_aci_session
from env import config
BASE_ACI_URL=config['ACI_BASE_URL']
username=config['ACI_USER']
password=config['ACI_PASSWORD']

#aci_session = get_authenticated_aci_session(config['ACI_USER'], config['ACI_PASSWORD'], config['ACI_BASE_URL']) #auth into ACI
url=f"{BASE_ACI_URL}/api/aaaLogin.json"
r = requests.post(url, json={"aaaUser":{"attributes":{"name":username,"pwd":password}}}, verify=False) #authenticate

token = r.json()["imdata"][0]["aaaLogin"]["attributes"]["token"]#get auth token

cookie = {'APIC-cookie':token}

#Fabric health----
url=f"{BASE_ACI_URL}/api/class/fabricHealthTotal.json"
r_h = requests.get(url, cookies=cookie, verify=False) #GET request total health

pprint(r_h.json())



with open('ACIhealth.csv', mode='w') as csv_file: #create csv and write data
    fieldnames = ['Timestamp', 'TotalHealthScore', 'MaximumSeverity']
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

    writer.writeheader()
    for i in r_h.json()['imdata']:
        writer.writerow({'Timestamp': i['fabricHealthTotal']['attributes']['modTs'], 'TotalHealthScore': i['fabricHealthTotal']['attributes']['cur'], 'MaximumSeverity': i['fabricHealthTotal']['attributes']['maxSev']})
   