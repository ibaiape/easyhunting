import requests
import os
import sys
import urllib.parse
import base64
import re
import configparser

config = configparser.ConfigParser()
config.read(os.path.dirname(sys.modules['__main__'].__file__) + '/config.ini')
api_key = config['apis']['virustotal']
headers = {'x-apikey': api_key, 'Accept': 'application/json'}


# Ref: https://developers.virustotal.com/reference/file-info
def get_a_file_report(id):
	url = "https://www.virustotal.com/api/v3/files/" + id
	try:
		r = requests.Session()
		r.headers.update(headers)
		res = r.get(url)
		if res.status_code != 200:
			#print(res.json().get('error').get('message'))
			#exit()
			return None, None
		else:
			return res.json()['data']['attributes'], res.json()['data']['id']
	except requests.exceptions.RequestException as error:
		print('virustotal: ' + str(error))
		return None, None

# Ref: https://developers.virustotal.com/reference/files-comments-get
def get_comments_on_a_file(id):
	url = "https://www.virustotal.com/api/v3/files/" + id + "/comments"
	try:
		res = requests.request("GET", url, headers=headers)
		if res.status_code != 200:
			#print(res.json().get('error').get('message'))
			pass
		else:
			return res.json()['data']
	except requests.exceptions.RequestException as error:
		print('virustotal: ' + str(error))

# Ref: https://developers.virustotal.com/reference/files-relationships
def get_objects_related_to_a_file(id, relationship):
	url = "https://www.virustotal.com/api/v3/files/" + id + "/" + relationship + "?limit=40"
	try:
		res = requests.request("GET", url, headers=headers)
		if res.status_code != 200:
			#print(res.json().get('error').get('message'))
			pass
		else:
			return res.json()['data']
	except requests.exceptions.RequestException as error:
		print('virustotal: ' + str(error))

# Ref: https://developers.virustotal.com/reference/files-download
# This endpoint is only available for users with special privileges.
def download_a_file(id, dir):
	url = "https://www.virustotal.com/api/v3/files/" + id + "/download"
	try:
		res = requests.request("GET", url, headers=headers)
		if res.status_code != 200:
			#print(res.json().get('error').get('message'))
			#exit()
			return False
		f = open(dir + id + ".fil", "wb")
		f.write(res.content)
		f.close()
		return True
	except requests.exceptions.RequestException as error:
		print('virustotal: ' + str(error))

# Ref: https://developers.virustotal.com/reference/file-all-behaviours-summary
def get_a_summary_of_all_behaviour_reports_for_a_file(id):
	url = "https://www.virustotal.com/api/v3/files/" + id + "/behaviour_summary"
	try:
		res = requests.request("GET", url, headers=headers)
		if res.status_code != 200:
			#print(res.json().get('error').get('message'))
			pass
		else:
			return res.json()['data']
	except requests.exceptions.RequestException as error:
		print('virustotal: ' + str(error))

# No Ref
def get_all_behaviour_reports_for_a_file(id):
	url = 'https://www.virustotal.com/api/v3/files/' + id + '/behaviours'
	try:
		res = requests.request("GET", url, headers=headers)
		if res.status_code != 200:
			#print(res.json().get('error').get('message'))
			pass
		else:
			return res.json()['data']
	except requests.exceptions.RequestException as error:
		print('virustotal: ' + str(error))

# Ref: https://developers.virustotal.com/reference/file_behaviourssandbox_idrelationship
def get_objects_related_to_a_behaviour_report(sanbox_id, relationship):
	url = 'https://www.virustotal.com/api/v3/file_behaviours/' + sanbox_id + '/' + relationship
	try:
		res = requests.request("GET", url, headers=headers)
		if res.status_code != 200:
			#print(res.json().get('error').get('message'))
			pass
		else:
			return res.json()['data']
	except requests.exceptions.RequestException as error:
		print('virustotal: ' + str(error))

# Ref: https://developers.virustotal.com/reference/get-sigma-analysis-id
def get_a_file_sigma_analysis(id):
	try:
		url = "https://www.virustotal.com/api/v3/sigma_analyses/" + id
		res = requests.request("GET", url, headers=headers)
		if res.status_code != 200:
			#print(res.json().get('error').get('message'))
			pass
			return False
		return res.json()['data']['attributes']
	except requests.exceptions.RequestException as error:
		print('virustotal: ' + str(error))

# Ref: https://developers.virustotal.com/reference/intelligence-search
# This endpoint is only available for users with special privileges.
def advanced_corpus_search(query, limit=15):
	try:
		url = 'https://www.virustotal.com/api/v3/intelligence/search?query=' + urllib.parse.quote(query) + '&limit='  + str(limit) + '&descriptors_only=false'
		res = requests.request("GET", url, headers=headers)
		if res.status_code != 200:
			#print(res.json().get('error').get('message'))
			#exit()
			pass
		else:
			return res.json()
	except requests.exceptions.RequestException as error:
		print('virustotal: ' + str(error))

# Ref: https://developers.virustotal.com/reference/files-analyse
def request_a_file_rescan(id):
	try:
		url = 'https://www.virustotal.com/api/v3/files/' + id + '/analyse'
		res = requests.request("POST", url, headers=headers)
		if res.status_code != 200:
			print(res.json().get('error').get('message'))
			exit()
		return res.json()
	except requests.exceptions.RequestException as error:
		print('virustotal: ' + str(error))

# Ref: https://developers.virustotal.com/reference/analysis
def get_a_file_analysis(id):
	try:
		url = 'https://www.virustotal.com/api/v3/analyses/' + id
		res = requests.request("GET", url, headers=headers)
		if res.status_code != 200:
			#print(res.json().get('error').get('message'))
			#exit()
			pass
		else:
			return res.json()
	except requests.exceptions.RequestException as error:
		print('virustotal: ' + str(error))

# Ref: https://developers.virustotal.com/reference/url-info
def get_a_url_analysis_report(url):
	try:
		url = 'https://www.virustotal.com/api/v3/urls/' + re.sub('=', '', str(base64.urlsafe_b64encode(bytes(url, 'utf-8')).decode()))
		res = requests.request("GET", url, headers=headers)
		if res.status_code != 200:
			#print(res.json().get('error').get('message'))
			#exit()
			return None, None
		else:
			return res.json()['data']['attributes'], res.json()['data']['id']
	except requests.exceptions.RequestException as error:
		print('virustotal: ' + str(error))

# Ref: https://developers.virustotal.com/reference/urls-comments-get
def get_comments_on_a_url(id):
	url = 'https://www.virustotal.com/api/v3/urls/' + id + '/comments'
	try:
		res = requests.request("GET", url, headers=headers)
		if res.status_code != 200:
			#print(res.json().get('error').get('message'))
			pass
		else:
			return res.json()['data']
	except requests.exceptions.RequestException as error:
		print('virustotal: ' + str(error))

# Ref: https://developers.virustotal.com/reference/urls-relationships
def get_objects_related_to_a_url(id, relationship):
	url = "https://www.virustotal.com/api/v3/urls/" + id + "/" + relationship + "?limit=40"
	try:
		res = requests.request("GET", url, headers=headers)
		if res.status_code != 200:
			#print(res.json().get('error').get('message'))
			pass
		else:
			return res.json()['data']
	except requests.exceptions.RequestException as error:
		print('virustotal: ' + str(error))

# Ref: https://developers.virustotal.com/reference/domain-info
def get_a_domain_report(domain):
	try:
		url = 'https://www.virustotal.com/api/v3/domains/' + domain
		res = requests.request("GET", url, headers=headers)
		if res.status_code != 200:
			#print(res.json().get('error').get('message'))
			#exit()
			return None, None
		else:
			return res.json()['data']['attributes'], res.json()['data']['id']
	except requests.exceptions.RequestException as error:
		print('virustotal: ' + str(error))

# Ref: https://developers.virustotal.com/reference/domains-comments-get
def get_comments_on_a_domain(domain):
	url = 'https://www.virustotal.com/api/v3/domains/' + domain + '/comments'
	try:
		res = requests.request("GET", url, headers=headers)
		if res.status_code != 200:
			#print(res.json().get('error').get('message'))
			pass
		else:
			return res.json()['data']
	except requests.exceptions.RequestException as error:
		print('virustotal: ' + str(error))

# Ref: https://developers.virustotal.com/reference/domains-relationships
def get_objects_related_to_a_domain(domain, relationship):
	url = "https://www.virustotal.com/api/v3/domains/" + domain + "/" + relationship + "?limit=40"
	try:
		res = requests.request("GET", url, headers=headers)
		if res.status_code != 200:
			#print(res.json().get('error').get('message'))
			pass
		else:
			return res.json()['data']
	except requests.exceptions.RequestException as error:
		print('virustotal: ' + str(error))

# Ref: https://developers.virustotal.com/reference/ip-info
def get_an_ip_address_report(ip):
	try:
		url = 'https://www.virustotal.com/api/v3/ip_addresses/' + ip
		res = requests.request("GET", url, headers=headers)
		if res.status_code != 200:
			#print(res.json().get('error').get('message'))
			#exit()
			return None, None
		else:
			return res.json()['data']['attributes'], res.json()['data']['id']
	except requests.exceptions.RequestException as error:
		print('virustotal: ' + str(error))

# Ref: https://developers.virustotal.com/reference/ip-comments-get
def get_comments_on_an_ip_address(ip):
	url = 'https://www.virustotal.com/api/v3/ip_addresses/' + ip + '/comments'
	try:
		res = requests.request("GET", url, headers=headers)
		if res.status_code != 200:
			#print(res.json().get('error').get('message'))
			pass
		else:
			return res.json()['data']
	except requests.exceptions.RequestException as error:
		print('virustotal: ' + str(error))

# Ref: https://developers.virustotal.com/reference/ip-relationships
def get_objects_related_to_an_ip_address(ip, relationship):
	url = "https://www.virustotal.com/api/v3/ip_addresses/" + ip + "/" + relationship + "?limit=40"
	try:
		res = requests.request("GET", url, headers=headers)
		if res.status_code != 200:
			#print(res.json().get('error').get('message'))
			pass
		else:
			return res.json()['data']
	except requests.exceptions.RequestException as error:
		print('virustotal: ' + str(error))
