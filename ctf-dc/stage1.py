import requests
import json
from pprint import pprint

from utils.auth import IntersightAuth, get_authenticated_aci_session
from env import config
BASE_URL='https://www.intersight.com/api/v1'
auth=IntersightAuth(secret_key_filename=config['INTERSIGHT_CERT'],
                      api_key_id=config['INTERSIGHT_API_KEY'])



url = f"{BASE_URL}/cond/Alarms" #query alarms params= ?$top=1

response = requests.get(url, auth=auth)

Alarm_Descriptions=[]
for i in response.json()['Results']:
    Alarm_Descriptions.append(i['Description']) #extract descriptions


print("Alarm descriptions: \n")
pprint(Alarm_Descriptions)
print("\n")
input("Press Enter to continue...")
#Physical infrastructure---------------

#pprint(response.json())
url = f"{BASE_URL}/compute/PhysicalSummaries" #query alarms params= ?$top=1

response = requests.get(url, auth=auth)


#i represents a single dictionary in the Results list in the response body
#Physical_Summary is a list of "summarized" dictionaries
Physical_Summary=[]
for i in response.json()['Results']:
    Physical_Summary.append({j: i[j] for j in ('ManagementMode', 'MgmtIpAddress', 'Name', 'NumCpus', 'NumCpuCores', 'OperPowerState','Firmware','Model','Serial','Tags')})

print("\n") 
print("Physical infrastructure summary: \n")
pprint(Physical_Summary)
print("\n")
input("Press Enter to continue...")
#HCL compliance-------------
url = f"{BASE_URL}/cond/HclStatuses" #query alarms params= ?$top=1
response = requests.get(url, auth=auth)
HCL_OSs=[]
for i in response.json()['Results']:
    HCL_OSs.append({j: i[j] for j in ('HclOsVendor', 'HclOsVersion')})

print("\n")
print("HCL OS versions and vendors : \n")
pprint(HCL_OSs)
print("\n")
input("Press Enter to continue...")
#Kubernetes clusters names ------------
url = f"{BASE_URL}/kubernetes/Clusters" #query alarms params= ?$top=1
response = requests.get(url, auth=auth)
Kubernetes_names=[]


for i in response.json()['Results']:
   Kubernetes_names.append(i['Name']) #extract descriptions

print("\n")
print("Kubernetes clusters names: \n")
pprint(Kubernetes_names)
print("\n")
input("Press Enter to continue...")
#Kubernetes deployments

url = f"{BASE_URL}/kubernetes/Deployments?" #query alarms params= ?$top=1
response = requests.get(url, auth=auth)
Kubernetes_deploy_number=0


for i in response.json()['Results']:
   Kubernetes_deploy_number+=1 #count kubernetes deployments

print("\n")
print("Number of Kubernetes deployments: \n")
print(Kubernetes_deploy_number)

