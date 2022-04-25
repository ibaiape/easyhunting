import requests
import json

url = 'https://threatfox-api.abuse.ch/api/v1/'
headers = {'accept': 'application/json'}

# ref: https://threatfox.abuse.ch/api/#search-ioc
def search_an_IOC(ioc):
	try:
		data = {'query': 'search_ioc', 'search_term': ioc}
		res = requests.request("POST", url, headers=headers, data=json.dumps(data))
		if res.status_code != 200:
			return
		response = json.loads(res.text)
		if response.get('query_status') != 'ok':
			return
		return response.get('data')[0]
	except requests.exceptions.RequestException as error:
		print('threatfox: ' + str(error))


# ref: https://threatfox.abuse.ch/api/#search-by-hash
def search_for_IOCs_by_file_hash(hash):
	try:
		data = {'query': 'search_hash', 'hash': hash}
		res = requests.request("POST", url, headers=headers, data=json.dumps(data))
		if res.status_code != 200:
			return
		response = json.loads(res.text)
		if response.get('query_status') != 'ok':
			return
		return response.get('data')
	except requests.exceptions.RequestException as error:
		print('threatfox: ' + str(error))