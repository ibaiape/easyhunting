import requests
import json

url_url = 'https://urlhaus-api.abuse.ch/v1/url/'
host_url = 'https://urlhaus-api.abuse.ch/v1/host/'
payload_url = 'https://urlhaus-api.abuse.ch/v1/payload/'
download_url = 'https://urlhaus-api.abuse.ch/v1/download/'
headers = {'accept': 'application/json'}

# ref: https://urlhaus-api.abuse.ch/#urlinfo
def query_url_information(url):
	try:
		data = {'url': url}
		res = requests.request("POST", url_url, headers=headers, data=data)
		if res.status_code != 200:
			return
		response = json.loads(res.text)
		if response.get('query_status') != 'ok':
			return
		return response
	except requests.exceptions.RequestException as error:
		print('urlhaus: ' + str(error))

# ref: https://urlhaus-api.abuse.ch/#hostinfo
def query_host_information(host):
	try:
		data = {'host': host}
		res = requests.request("POST", host_url, headers=headers, data=data)
		if res.status_code != 200:
			return
		response = json.loads(res.text)
		if response.get('query_status') != 'ok':
			return
		return response
	except requests.exceptions.RequestException as error:
		print('urlhaus: ' + str(error))

# ref: https://urlhaus-api.abuse.ch/#payloadinfo
def query_payload_information(hash):
	try:
		hashtype = 'sha256_hash'
		if len(hash) == 32:
			hashtype = 'md5_hash'
		data = {hashtype: hash}
		res = requests.request("POST", payload_url, headers=headers, data=data)
		if res.status_code != 200:
			return
		response = json.loads(res.text)
		if response.get('query_status') != 'ok':
			return
		return response
	except requests.exceptions.RequestException as error:
		print('urlhaus: ' + str(error))

# ref: https://urlhaus-api.abuse.ch/#download-sample
def download_malware_sample(sha256, dir):
	try:
		res = requests.request("GET", download_url + sha256, headers=headers)
		if res.status_code != 200:
			return False
		if 'query_status' in res.text:
			return False
		f = open(dir + sha256 + ".fil", "wb")
		f.write(res.content)
		f.close()
		return True
	except requests.exceptions.RequestException as error:
		print('urlhaus: ' + str(error))