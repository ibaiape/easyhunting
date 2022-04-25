import requests
import json
import configparser

ip_url = 'http://otx.alienvault.com/api/v1/indicators/IPv4/'
domain_url = 'http://otx.alienvault.com/api/v1/indicators/domain/'
url_url = 'http://otx.alienvault.com/api/v1/indicators/url/'
file_url = 'http://otx.alienvault.com/api/v1/indicators/file/'

headers = {'accept': 'application/json'}

def ip_search(ip):
	data = dict()
	sections = ['general', 'malware', 'url_list', 'passive_dns']
	for section in sections:
		data[section] = internal_ip_search(ip, section)
	return data


# ref: https://otx.alienvault.com/assets/static/external_api.html#panel_api_v1_indicators_IPv4__ip___section_
def internal_ip_search(ip, section):
	try:
		params = {'limit': 10}
		res = requests.request("POST", ip_url + ip + "/" + section, headers=headers, params=params)
		if res.status_code != 200:
			return
		response = json.loads(res.text)
		return response
	except requests.exceptions.RequestException as error:
		print('alienvault: ' + str(error))

def domain_search(domain):
	data = dict()
	sections = ['general', 'malware', 'url_list', 'passive_dns']
	for section in sections:
		data[section] = internal_domain_search(domain, section)
	return data

# ref: https://otx.alienvault.com/assets/static/external_api.html#panel_api_v1_indicators_domain__domain___section_
def internal_domain_search(domain, section):
	try:
		params = {'limit': 10}
		res = requests.request("POST", domain_url + domain + "/" + section, headers=headers, params=params)
		if res.status_code != 200:
			return
		response = json.loads(res.text)
		return response
	except requests.exceptions.RequestException as error:
		print('alienvault: ' + str(error))


def url_search(url):
	data = dict()
	sections = ['general', 'url_list']
	for section in sections:
		data[section] = internal_url_search(url, section)
	return data

# ref: https://otx.alienvault.com/assets/static/external_api.html#panel_api_v1_indicators_url__url___section_
def internal_url_search(url,section):
	try:
		params = {'limit': 10}
		res = requests.request("POST", url_url + url + "/" + section, headers=headers, params=params)
		if res.status_code != 200:
			return
		response = json.loads(res.text)
		return response
	except requests.exceptions.RequestException as error:
		print('alienvault: ' + str(error))

def file_search(url):
	data = dict()
	sections = ['general', 'analysis']
	for section in sections:
		data[section] = internal_file_search(url, section)
	return data

# ref: https://otx.alienvault.com/assets/static/external_api.html#panel_api_v1_indicators_file__file_hash___section_
def internal_file_search(hash, section):
	try:
		params = {'limit': 10}
		res = requests.request("POST", file_url + hash + "/" + section, headers=headers, params=params)
		if res.status_code != 200:
			return
		response = json.loads(res.text)
		return response
	except requests.exceptions.RequestException as error:
		print('alienvault: ' + str(error))
	