import requests
import json

url = 'https://mb-api.abuse.ch/api/v1/'
headers = {'accept': 'application/json'}

# ref: https://bazaar.abuse.ch/api/#query_hash
def query_a_malware_sample(hash):
	try:
		data = {'query':'get_info', 'hash': hash}
		res = requests.request("POST", url, headers=headers, data=data)
		if res.status_code != 200:
			return
		response = json.loads(res.text)
		if response.get('query_status') != 'ok':
			return
		return response['data'][0]
	except requests.exceptions.RequestException as error:
		print('bazaar: ' + str(error))

# ref: https://bazaar.abuse.ch/api/#download
def download_a_malware_sample(sha256, dir):
	try:
		data = {'query':'get_file', 'sha256_hash': sha256}
		res = requests.request("POST", url, headers=headers, data=data)
		if res.status_code != 200:
			return False
		if 'query_status' in res.text:
			return False
		f = open(dir + sha256 + ".fil", "wb")
		f.write(res.content)
		f.close()
		return True
	except requests.exceptions.RequestException as error:
		print('bazaar: ' + str(error))

# ref: https://bazaar.abuse.ch/api/#imphas
def query_imphash(imphash, limit=5):
	try:
		data = {'query':'get_imphash', 'imphash': imphash, 'limit': limit}
		res = requests.request("POST", url, headers=headers, data=data)
		if res.status_code != 200:
			return
		response = json.loads(res.text)
		if response.get('query_status') != 'ok':
			return
		return response['data']
	except requests.exceptions.RequestException as error:
		print('bazaar: ' + str(error))

# ref: https://bazaar.abuse.ch/api/#tlsh
def query_tlsh(tlsh, limit=5):
	try:
		data = {'query':'get_tlsh', 'tlsh': tlsh, 'limit': limit}
		res = requests.request("POST", url, headers=headers, data=data)
		if res.status_code != 200:
			return
		response = json.loads(res.text)
		if response.get('query_status') != 'ok':
			return
		return response['data']
	except requests.exceptions.RequestException as error:
		print('bazaar: ' + str(error))

# ref: https://bazaar.abuse.ch/api/#dhash_icon
def query_icon_dhash(dhash, limit=5):
	try:
		data = {'query':'get_dhash_icon', 'dhash_icon': dhash, 'limit': limit}
		res = requests.request("POST", url, headers=headers, data=data)
		if res.status_code != 200:
			return
		response = json.loads(res.text)
		if response.get('query_status') != 'ok':
			return
		return response['data']
	except requests.exceptions.RequestException as error:
		print('bazaar: ' + str(error))

# ref: https://bazaar.abuse.ch/api/#taginfo
def query_tag(tag, limit=10):
	try:
		data = {'query':'get_taginfo', 'tag': tag, 'limit': limit}
		res = requests.request("POST", url, headers=headers, data=data)
		if res.status_code != 200:
			return
		response = json.loads(res.text)
		if response.get('query_status') != 'ok':
			return
		return response['data']
	except requests.exceptions.RequestException as error:
		print('bazaar: ' + str(error))

# ref: https://bazaar.abuse.ch/api/#subject_cn
def subject_cn_sign(cn, limit=5):
	try:
		data = {'query':'get_subjectinfo', 'subject_cn': cn, 'limit': limit}
		res = requests.request("POST", url, headers=headers, data=data)
		if res.status_code != 200:
			return
		response = json.loads(res.text)
		if response.get('query_status') != 'ok':
			return
		return response['data']
	except requests.exceptions.RequestException as error:
		print('bazaar: ' + str(error))