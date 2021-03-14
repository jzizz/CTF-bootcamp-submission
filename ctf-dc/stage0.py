import requests
import json
from pprint import pprint

from utils.auth import IntersightAuth, get_authenticated_aci_session
from env import config
BASE_URL='https://www.intersight.com/api/v1'
auth=IntersightAuth(secret_key_filename=config['INTERSIGHT_CERT'],
                      api_key_id=config['INTERSIGHT_API_KEY'])



url = f"{BASE_URL}/ntp/Policies" #query ntp policies

response = requests.get(url, auth=auth)

pprint(response.json())