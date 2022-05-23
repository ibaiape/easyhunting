import datetime
from py_console import console, bgColor, textColor
from tabulate import tabulate

from intelligence.apis.virustotal import *
from utils.malapi import print_malapi_matches
from utils.colors import colors
from pefil.modules import pe

import intelligence.bazaar_intel as bazaar_intel
import intelligence.triage_intel as triage_intel

def get_tag_from_relationship(id, target_relationships, intel_type, tag, min=1):
	mayor_detected = 0
	present = 0 # just for known_download_from_itw relationships
	for relationship in target_relationships:
		if intel_type == 'file':
			related_objects = get_objects_related_to_a_file(id, relationship)
		elif intel_type == 'url':
			related_objects = get_objects_related_to_a_url(id, relationship)
		elif intel_type == 'domain':
			related_objects = get_objects_related_to_a_domain(id, relationship)
		elif intel_type == 'ip':
			related_objects = get_objects_related_to_an_ip_address(id, relationship)
		else:
			return
		if related_objects:
			for related_object in related_objects:
				present = 1
				if related_object.get('attributes') and related_object.get('attributes').get('last_analysis_stats').get("malicious") > mayor_detected:
						mayor_detected = related_object.get('attributes').get('last_analysis_stats').get("malicious")
		if tag == 'known_download_from_itw' and present:
			return tag + '(' + str(mayor_detected) + ')'
		elif tag != 'known_download_from_itw' and mayor_detected >= min:
			return tag + '(' + str(mayor_detected) + ')'

def vt_file_search(id, banner=True):
	file_report, id = get_a_file_report(id)
	if file_report:
		if banner:
			print(f'intel from {console.highlight("virustotal", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}\n')
		print(str(file_report.get('last_analysis_stats').get('malicious')) + ' avs\t', end = '' )
		print(f'{colors.OK}' + pe.get_printable_name(file_report.get('meaningful_name'), file_report.get('md5'), file_report.get('sha256')) + f'{colors.RESET}' if file_report.get('last_analysis_stats').get('malicious') == 0 else f'{colors.ATTENTION}' + pe.get_printable_name(file_report.get('meaningful_name'), file_report.get('md5'), file_report.get('sha256')) + f'{colors.RESET}', end = '')
		print('\t' + pe.get_printable_size(file_report.get('size')) + '\t' + 'fs: ' + str(datetime.datetime.fromtimestamp(file_report.get('first_submission_date')).isoformat()) + '\t' + 'lastscan: ' + str((datetime.datetime.today() - datetime.datetime.fromtimestamp(file_report.get('last_analysis_date'))).days) + ' days ago' + '\t' + id)
		if file_report.get('tags'):
			print('\ttags: ', end = '')
			for tag in file_report.get('tags'):
				print(f'{console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}', end = ' ')
			print()
		if file_report.get('capabilities_tags'):
			print('\tcapabilities: ', end = '')
			for tag in file_report.get('capabilities_tags'):
				print(f'{console.highlight(tag, bgColor=bgColor.BLUE, textColor=textColor.WHITE)}', end = ' ')
			print()

		have = list()

		if file_report.get('crowdsourced_yara_results'):
			have.append('yara')
		if get_a_file_sigma_analysis(id):
			have.append('sigma')
		if file_report.get('crowdsourced_ids_results'):
			have.append('ids')

		known_download_from_itw = get_tag_from_relationship(id, target_relationships=['itw_urls', 'itw_domains', 'itw_ips'], intel_type='file', tag='known_download_from_itw', min=0)
		if known_download_from_itw:
			have.append(known_download_from_itw)
		contacted_network = get_tag_from_relationship(id, target_relationships=['contacted_urls', 'contacted_domains', 'contacted_ips'], intel_type='file', tag='contacted_network', min=1)
		if contacted_network:
			have.append(contacted_network)
		embedded_ioc = get_tag_from_relationship(id, target_relationships=['embedded_urls', 'embedded_domains', 'embedded_ips'], intel_type='file', tag='embedded_ioc', min=1)
		if embedded_ioc:
			have.append(embedded_ioc)
		detected_parent = get_tag_from_relationship(id, target_relationships=['execution_parents', 'compressed_parents'], intel_type='file', tag='detected_parent', min=1)
		if detected_parent:
			have.append(detected_parent)
		dropped_file = get_tag_from_relationship(id, target_relationships=['dropped_files'], intel_type='file', tag='dropped_file', min=1)
		if dropped_file:
			have.append(dropped_file)
		
		if get_comments_on_a_file(id):
			have.append('comments')
		if have:
			print('\thave: ', end='')
			for h in have:
				print(f'{console.highlight(h, bgColor=bgColor.RED, textColor=textColor.WHITE)}', end = ' ')
			print()

		ttps = vt_get_mitre(id, banner=False)
		if ttps:
			print('\tttps: ', end='')
			for t in ttps:
				print(f'{console.highlight(t, bgColor=bgColor.WHITE, textColor=textColor.BLACK)}', end = ' ')
			print()
		print('\tlink: ' + 'https://www.virustotal.com/gui/file/' + id)
		print('\treports: ')
		main_avs = ['Panda', 'Avast', 'Avira', 'BitDefender', 'ESET-NOD32', 'F-Secure', 'FireEye', 'Fortinet', 'Kaspersky', 'MalwareBytes', 'McAfee', 'Microsoft', 'Sophos', 'Symantec', 'TrendMicro', 'Zone-Alarm']
		for av in main_avs:
			if file_report.get('last_analysis_results').get(av):
				if file_report.get('last_analysis_results').get(av).get('result'):
					if 'malicious' in file_report.get('last_analysis_results').get(av).get('category'):
						print(f"\t\t{colors.ATTENTION}" + av + ': ' + file_report.get('last_analysis_results').get(av).get('result') + f"{colors.RESET}")
					else:
						print('\t\t' + av + ': ' + file_report.get('last_analysis_results').get(av).get('result'))
				else:
					if 'malicious' in file_report.get('last_analysis_results').get(av).get('category'):
						print(f"\\tt{colors.ATTENTION}" + av + ': ' + file_report.get('last_analysis_results').get(av).get('category') + f"{colors.RESET}")
					else:
						print('\t\t' + av + ': ' + file_report.get('last_analysis_results').get(av).get('category'))
		print()
		return True
	return False

def vt_print_tags(id):
	tags = vt_tags(id)
	if tags:
		print(f'{console.highlight("virustotal", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}', end = ' ')
		print(': ', end=' ')
		for tag in tags:
			print(f'{console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}', end = ' ')
		print()

def vt_tags(id):
	file_report, id = get_a_file_report(id)
	if file_report:
		tags = list()
		tags.append('detection:' + str(file_report.get('last_analysis_stats').get('malicious')))
		if file_report.get('tags'):
			for tag in file_report.get('tags'):
				tags.append(tag)
		if file_report.get('capabilities_tags'):
			for tag in file_report.get('capabilities_tags'):
				tags.append(tag)
		return tags
		
def vt_url_search(url):
	url_report, id = get_a_url_analysis_report(url)
	if url_report:
		print(f'intel from {console.highlight("virustotal", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}\n')
		print(str(url_report.get('last_analysis_stats').get('malicious')) + ' avs\t', end = '' )
		print(f'{colors.OK}' + url + f'{colors.RESET}' if url_report.get('last_analysis_stats').get('malicious') == 0 else f'{colors.ATTENTION}' + url + f'{colors.RESET}', end = '')
		print('\t' + 'fs: ' + str(datetime.datetime.fromtimestamp(url_report.get('first_submission_date')).isoformat()) + '\t' + 'lastscan: ' + str((datetime.datetime.today() - datetime.datetime.fromtimestamp(url_report.get('last_analysis_date'))).days) + ' days ago')
		if url_report.get('tags'):
			print('\ttags: ', end = '')
			console.setShowTimeDefault(False)
			for tag in url_report.get('tags'):
				print(f'{console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}', end = ' ')
			print()

		have = list()

		downloaded_files = get_tag_from_relationship(id, target_relationships=['downloaded_files'], intel_type='url', tag='downloaded_file', min=1)
		if downloaded_files:
			have.append(downloaded_files)
		related_files = get_tag_from_relationship(id, target_relationships=['communicating_files', 'referrer_files'], intel_type='url', tag='related_file', min=1)
		if related_files:
			have.append(related_files)
		
		if get_comments_on_a_url(id):
			have.append('comments')

		if have:
			print('\thave: ', end='')
			for h in have:
				print(f'{console.highlight(h, bgColor=bgColor.RED, textColor=textColor.WHITE)}', end = ' ')
			print()
		print('\tlink: ' + 'https://www.virustotal.com/gui/url/' + id + '\n')

def vt_domain_search(domain):
	domain_report, id = get_a_domain_report(domain)
	if domain_report:
		print(f'intel from {console.highlight("virustotal", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}\n')
		print(str(domain_report.get('last_analysis_stats').get('malicious')) + ' avs\t', end = '' )
		print(f'{colors.OK}' + domain + f'{colors.RESET}' if domain_report.get('last_analysis_stats').get('malicious') == 0 else f'{colors.ATTENTION}' + domain + f'{colors.RESET}', end = '')
		if domain_report.get('creation_date'):
			print('\t' + 'creation_date: ' + str(datetime.datetime.fromtimestamp(domain_report.get('creation_date')).isoformat()))
		else:
			print('\t' + 'creation_date: unknown')
		if domain_report.get('tags'):
			print('\ttags: ', end = '')
			console.setShowTimeDefault(False)
			for tag in domain_report.get('tags'):
				print(f'{console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}', end = ' ')
			print()

		have = list()

		downloaded_files = get_tag_from_relationship(id, target_relationships=['downloaded_files'], intel_type='domain', tag='downloaded_file', min=1)
		if downloaded_files:
			have.append(downloaded_files)
		related_network = get_tag_from_relationship(id, target_relationships=['subdomains', 'urls'], intel_type='domain', tag='related_network', min=1)
		if related_network:
			have.append(related_network)
		related_files = get_tag_from_relationship(id, target_relationships=['communicating_files', 'referrer_files'], intel_type='domain', tag='related_file', min=1)
		if related_files:
			have.append(related_files)
		
		if get_comments_on_a_domain(id):
			have.append('comments')

		if have:
			print('\thave: ', end='')
			for h in have:
				print(f'{console.highlight(h, bgColor=bgColor.RED, textColor=textColor.WHITE)}', end = ' ')
			print()
		print('\tlink: ' + 'https://www.virustotal.com/gui/domain/' + id + '\n')

def vt_ip_search(ip):
	ip_report, id = get_an_ip_address_report(ip)
	if ip_report:
		print(f'intel from {console.highlight("virustotal", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}\n')
		print(str(ip_report.get('last_analysis_stats').get('malicious')) + ' avs\t', end = '' )
		print(f'{colors.OK}' + ip + f'{colors.RESET}' if ip_report.get('last_analysis_stats').get('malicious') == 0 else f'{colors.ATTENTION}' + ip + f'{colors.RESET}', end = '')
		print('\t' + 'owner: ' + str(ip_report.get('as_owner')))
		if ip_report.get('tags'):
			print('\ttags: ', end = '')
			console.setShowTimeDefault(False)
			for tag in ip_report.get('tags'):
				print(f'{console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}', end = ' ')
			print()

		have = list()

		downloaded_files = get_tag_from_relationship(id, target_relationships=['downloaded_files'], intel_type='ip', tag='downloaded_file', min=1)
		if downloaded_files:
			have.append(downloaded_files)
		related_network = get_tag_from_relationship(id, target_relationships=['urls'], intel_type='ip', tag='related_network', min=1)
		if related_network:
			have.append(related_network)
		related_files = get_tag_from_relationship(id, target_relationships=['communicating_files', 'referrer_files'], intel_type='ip', tag='related_file', min=1)
		if related_files:
			have.append(related_files)
		
		if get_comments_on_an_ip_address(ip):
			have.append('comments')

		if have:
			print('\thave: ', end='')
			for h in have:
				print(f'{console.highlight(h, bgColor=bgColor.RED, textColor=textColor.WHITE)}', end = ' ')
			print()
		print('\tlink: ' + 'https://www.virustotal.com/gui/ip-address/' + id + '\n')

def vt_intelligence(query, limit=15):
	max_tags = 4
	search_res = advanced_corpus_search(query, limit)
	if search_res:
		print('vti query -> ' + f'{console.highlight(query, bgColor=bgColor.WHITE, textColor=textColor.BLACK)}')
		if search_res.get('meta').get('total_hits'):
			print('hits: ' + str(search_res.get('meta').get('total_hits')))
		elif search_res.get('meta').get('count'):
			print('hits: ' + str(search_res.get('meta').get('count')))
		print('link: ' + 'https://www.virustotal.com/gui/search/' + urllib.parse.quote(query))
		print()
		data = list()
		headers = ['avs', 'name + tags', 'type', 'size', 'first_seen', 'last_seen', 'sha256']
		for file in search_res.get('data'):
			row = list()
			id = file.get('id')
			file = file.get('attributes')
			tags = ''
			if file.get('tags'):
				tags += '\n'
				for tag in file.get('tags')[:max_tags]:
					tags = tags + console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK) + ' '
				if len(file.get('tags')) >= max_tags:
					tags = tags + console.highlight("+", bgColor=bgColor.YELLOW, textColor=textColor.BLACK) + ' '
			if file.get('capabilities_tags'):
				tags += '\n'
				for tag in file.get('capabilities_tags')[:max_tags]:
					tags = tags + console.highlight(tag, bgColor=bgColor.BLUE, textColor=textColor.WHITE) + ' '
				if len(file.get('capabilities_tags')) >= max_tags:
					tags = tags + console.highlight("+", bgColor=bgColor.BLUE, textColor=textColor.WHITE) + ' '
			more_intel = bazaar_intel.bazaar_tags(id)
			if more_intel:
				tags += '\n' + console.highlight("+bazaar", bgColor=bgColor.BLUE, textColor=textColor.WHITE) + ' '
				for tag in more_intel[:max_tags]:
					tags = tags + console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK) + ' '
				if len(more_intel) >= max_tags:
					tags = tags + console.highlight("+", bgColor=bgColor.YELLOW, textColor=textColor.BLACK) + ' '
			more_intel = triage_intel.triage_tags(id)
			if more_intel:
				tags += '\n' + console.highlight("+triage", bgColor=bgColor.BLUE, textColor=textColor.WHITE) + ' '
				for tag in more_intel[:max_tags]:
					tags = tags + console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK) + ' '
				if len(more_intel) >= max_tags:
					tags = tags + console.highlight("+", bgColor=bgColor.YELLOW, textColor=textColor.BLACK) + ' '
			row.append(str(file.get('last_analysis_stats').get('malicious')))
			row.append(f'{colors.ATTENTION}' + pe.get_printable_name(file.get('meaningful_name'), file.get('md5'), file.get('sha256')) + f'{colors.RESET}' + tags if file.get('last_analysis_stats').get('malicious') > 0 else f'{colors.OK}' + pe.get_printable_name(file.get('meaningful_name'), file.get('md5'), file.get('sha256')) + f'{colors.RESET}' + tags)
			row.append(str(file.get('type_tag')))
			row.append(pe.get_printable_size(file.get('size')))
			row.append(str(datetime.datetime.fromtimestamp(file.get('first_submission_date')).isoformat()).split('T')[0])
			row.append(str(datetime.datetime.fromtimestamp(file.get('last_submission_date')).isoformat()).split('T')[0])
			row.append(str(id))
			data.append(row)
		if data:
			print(tabulate(data, headers = headers, tablefmt = 'grid'))

def similar_by_vt_intelligence(query, limit=15):
	search_res = advanced_corpus_search(query, limit)
	files_result = list()
	if search_res:
		data = search_res.get('data')
		if data:
			for file in data:
				fil = dict()
				fil['sha256'] = file.get('id')
				fil['md5'] = file.get('attributes').get('md5')
				fil['filetype'] = file.get('attributes').get('type_tag')
				fil['size'] = file.get('attributes').get('size')
				fil['filename'] = file.get('attributes').get('meaningful_name')
				fil['tags'] = file.get('attributes').get('tags')
				files_result.append(fil)
	return files_result
				

def vt_similar_files(similars, hashes, limit, size, version_strings, subject_cn):
	similar_hashes = dict()
	if get_a_file_report(hashes['sha256'])[0]:
		similar_hashes['similar-to'] = hashes['sha256']
	if hashes['imphash']:
		similar_hashes['imphash'] = hashes['imphash']
	if hashes.get('tlsh'):
		similar_hashes['tlsh'] = hashes['tlsh']
	if hashes.get('ssdeep'):
		similar_hashes['ssdeep'] = hashes['ssdeep']
	if hashes.get('dhash'):
		similar_hashes['main_icon_dhash'] = hashes['dhash']
	if similar_hashes:
		for hash in similar_hashes:
			query = hash + ':"' + similar_hashes.get(hash) + '"'
			if hash == 'main_icon_dhash': # give a common name
				hash = 'dhash'
			elif hash == 'similar-to':
				hash = 'vt_similar_to'
			files = similar_by_vt_intelligence(query, limit)
			for fil in files:	
				if not similars.get(fil.get('sha256')):
					new_one = dict()
					new_one['sha256'] = fil.get('sha256')
					new_one['md5'] = fil.get('md5')
					new_one['filename'] = fil.get('filename')
					new_one['type'] = fil.get('filetype')
					new_one['size'] = fil.get('size')
					new_one['similar'] = set()
					new_one['similar'].add(hash)
					if (fil.get('size') >= size * 0.95) and (fil.get('size') <= size * 1.05):
						new_one['similar'].add('size')
					similars[fil.get('sha256')] = new_one
				else:
					update = similars.get(fil.get('sha256'))
					if not fil.get('filename'):
						update['filename'] = fil.get('filename')
					update['similar'].add(hash)
					if (fil.get('size') >= size * 0.95) and (fil.get('size') <= size * 1.05):
						update['similar'].add('size')
					similars[fil.get('sha256')] = update
	if version_strings:
		targets = ['InternalName', 'OriginalFilename', 'CompanyName', 'FileDescription'] # order by the most accurate (for me)
		for string in targets:
			if not version_strings.get(string):
				continue
			query = 'metadata:"' + version_strings.get(string) + '"'
			files = similar_by_vt_intelligence(query, limit)
			for fil in files:
				if not similars.get(fil.get('sha256')):
					new_one = dict()
					new_one['sha256'] = fil.get('sha256')
					new_one['md5'] = fil.get('md5')
					new_one['filename'] = fil.get('filename')
					new_one['type'] = fil.get('filetype')
					new_one['size'] = fil.get('size')
					new_one['similar'] = set()
					new_one['similar'].add('version')
					if (fil.get('size') >= size * 0.95) and (fil.get('size') <= size * 1.05):
						new_one['similar'].add('size')
					similars[fil.get('sha256')] = new_one
				else:
					update = similars.get(fil.get('sha256'))
					if not fil.get('filename'):
						update['filename'] = fil.get('filename')
					update['similar'].add('version')
					if (fil.get('size') >= size * 0.95) and (fil.get('size') <= size * 1.05):
						update['similar'].add('size')
					similars[fil.get('sha256')] = update
			if len(files) > 0: # when files are found with some word of the ordered list, break it to avoid too much matches
				break
	if subject_cn:
		query = 'signature:"' + subject_cn + '"'
		files = similar_by_vt_intelligence(query, limit)
		for fil in files:
			if not similars.get(fil.get('sha256')):
				new_one = dict()
				new_one['sha256'] = fil.get('sha256')
				new_one['md5'] = fil.get('md5')
				new_one['filename'] = fil.get('filename')
				new_one['type'] = fil.get('filetype')
				new_one['size'] = fil.get('size')
				new_one['similar'] = set()
				new_one['similar'].add('sign')
				if (fil.get('size') >= size * 0.95) and (fil.get('size') <= size * 1.05):
					new_one['similar'].add('size')
				similars[fil.get('sha256')] = new_one
			else:
				update = similars.get(fil.get('sha256'))
				if not fil.get('filename'):
					update['filename'] = fil.get('filename')
				update['similar'].add('sign')
				if (fil.get('size') >= size * 0.95) and (fil.get('size') <= size * 1.05):
					update['similar'].add('size')
				similars[fil.get('sha256')] = update

def vt_download_a_file(id, path):
	return download_a_file(id, path)

def vt_get_rules(id):
	file_report, id = get_a_file_report(id)
	if file_report:
		sigmas = get_a_file_sigma_analysis(id)
		if file_report.get('crowdsourced_yara_results') or (sigmas and sigmas.get('rule_matches')) or file_report.get('crowdsourced_ids_results'):
			print(f'rules from {console.highlight("virustotal", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}')
		#yaras
		if file_report.get('crowdsourced_yara_results'):
			print('\t' + f'{console.highlight("yara", bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}')
			yara_rules = set()
			for yara in file_report.get('crowdsourced_yara_results'):
				yara_rules.add(yara.get('description'))
			for yara in yara_rules:
				print('\t\t* ' + yara)
			print()
		#sigmas
		if sigmas and sigmas.get('rule_matches'):
			print('\t' + f'{console.highlight("sigma", bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}')
			sigma_rules = set()
			for sigma in sigmas.get('rule_matches'):
				sigma_rules.add(sigma.get('rule_description'))
			for sigma in sigma_rules:
				print('\t\t* ' + sigma)
			print()
		#idss
		if file_report.get('crowdsourced_ids_results'):
			print('\t' + f'{console.highlight("ids", bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}')
			ids_rules = set()
			for ids in file_report.get('crowdsourced_ids_results'):
				ids_rules.add(ids.get('rule_msg'))
			for ids in ids_rules:
				print('\t\t* ' + ids)
			print()

def vt_get_mitre(id, banner=True):
	summary_behaviour = get_a_summary_of_all_behaviour_reports_for_a_file(id)
	if summary_behaviour and summary_behaviour.get('attack_techniques'):
		mitre = set()
		for technique in summary_behaviour.get('attack_techniques').keys():
			mitre.add(technique)
		if mitre and banner:
			print(f'{console.highlight("virustotal", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}', end=' ')
		return list(mitre)


def vt_get_files_from_tag(tag, limit):
	search_res = advanced_corpus_search('engines:' + tag, limit)
	data = list()
	max_tags = 5
	headers = ['name + tags', 'type', 'size', 'first_seen', 'last_seen', 'sha256']
	if not search_res:
		return
	print('from ' + f'{console.highlight("virustotal", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}')
	for file in search_res.get('data'):
		row = list()
		id = file.get('id')
		file = file.get('attributes')
		tags = ''
		if file.get('tags'):
			tags = '\n'
			for tag in file.get('tags')[:max_tags]:
				tags = tags + ' ' + console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)
			if len(file.get('tags')) > max_tags:
				tags = tags + ' ' + console.highlight("+", bgColor=bgColor.YELLOW, textColor=textColor.BLACK)
		if file.get('capabilities_tags'):
			tags = '\n'
			for tag in file.get('capabilities_tags')[:max_tags]:
				tags = tags + ' ' + console.highlight(tag, bgColor=bgColor.BLUE, textColor=textColor.WHITE)
			if len(file.get('tags')) > max_tags:
				tags = tags + ' ' + console.highlight("+", bgColor=bgColor.BLUE, textColor=textColor.WHITE)
		row.append(f'{colors.ATTENTION}' + pe.get_printable_name(file.get('meaningful_name'), file.get('md5'), file.get('sha256')) + f'{colors.RESET}' + tags)
		row.append(str(file.get('type_tag')))
		row.append(pe.get_printable_size(file.get('size')))
		row.append(str(datetime.datetime.fromtimestamp(file.get('first_submission_date')).isoformat()).split('T')[0])
		row.append(str(datetime.datetime.fromtimestamp(file.get('last_submission_date')).isoformat()).split('T')[0])
		row.append(str(id))
		data.append(row)
	print(tabulate(data, headers = headers, tablefmt = 'grid') + '\n')
		