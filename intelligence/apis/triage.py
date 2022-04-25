import requests
import json
import configparser
import os
import sys

url = 'https://api.tria.ge/v0/'

config = configparser.ConfigParser()
config.read(os.path.dirname(sys.modules['__main__'].__file__) + '/config.ini')
api_key = config['apis']['triage']
headers = {'accept': 'application/json', 'Authorization':'Bearer ' + api_key}

def exist_file_report(sha256):
	try:
		query = 'sha256:' + sha256
		res = requests.request("GET", url + "search?query=" + query, headers=headers)
		if res.status_code != 200:
			return False
		response = json.loads(res.text)
		if not response.get('data'):
			return False
		return True
	except requests.exceptions.RequestException as error:
		print('triage: ' + str(error))


# ref: https://tria.ge/docs/cloud-api/samples/#get-search
def get_search(query):
	try:
		res = requests.request("GET", url + "search?query=" + query, headers=headers)
		if res.status_code != 200:
			return
		response = json.loads(res.text)
		if not response.get('data'):
			return
		return response.get('data')
	except requests.exceptions.RequestException as error:
		print('triage: ' + str(error))

# ref: https://tria.ge/docs/cloud-api/samples/#get-samplessampleidoverviewjson
def get_sample_overview(id):
	try:
		res = requests.request("GET", url + "samples/" + id + "/overview.json", headers=headers)
		if res.status_code != 200:
			return
		response = json.loads(res.text)
		return response
	except requests.exceptions.RequestException as error:
		print('triage: ' + str(error))

# ref: https://tria.ge/docs/cloud-api/samples/#get-samplessampleidsample
def download_a_file(hash, id, dir):
	try:
		res = requests.request("GET", url + "samples/" + id + "/sample", headers=headers)
		if res.status_code != 200:
			return False
		f = open(dir + hash + ".fil", "wb")
		f.write(res.content)
		f.close()
		return True
	except requests.exceptions.RequestException as error:
		print('triage: ' + str(error))
