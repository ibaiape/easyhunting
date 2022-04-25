import json
from py_console import console, bgColor, textColor
from utils.colors import colors
from tabulate import tabulate

from intelligence.apis import triage
from pefil.modules import pe

def triage_file_search(hash, banner=True):
	hashtype = 'md5'
	if len(hash) == 64:
		hashtype = 'sha256'
	report_info = triage.get_search(hashtype + ':' + hash)
	if not report_info:
		return False
	report_info = report_info[0] # the most recent
	file_report = triage.get_sample_overview(report_info.get('id'))
	if not file_report:
		return False
	if banner:
		print(f'intel from {console.highlight("triage", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}\n')
	score = file_report.get('sample').get('score')
	print(str(score) + '/10\t' if score else '0/10\t', end = '' )
	if not score or score < 5:
		print(f'{colors.OK}' + pe.get_printable_name(report_info.get('filename'), file_report.get('targets')[0].get('md5'), file_report.get('targets')[0].get('sha256')) + f'{colors.RESET}', end = '')
	elif score < 8:
		print(f'{colors.WARNING}' + pe.get_printable_name(report_info.get('filename'), file_report.get('targets')[0].get('md5'), file_report.get('targets')[0].get('sha256')) + f'{colors.RESET}', end = '')
	else:
		print(f'{colors.ATTENTION}' + pe.get_printable_name(report_info.get('filename'), file_report.get('targets')[0].get('md5'), file_report.get('targets')[0].get('sha256')) + f'{colors.RESET}', end = '')
	print('\t' + pe.get_printable_size(file_report.get('sample').get('size')) + '\t' + 'ls: ' + str(file_report.get('sample').get('created')) + '\t' + str(file_report.get('sample').get('sha256')))
	if file_report.get('analysis') and file_report.get('analysis').get('tags'):
		print('\ttags: ', end = '')
		for tag in file_report.get('analysis').get('tags'):
			print(f'{console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}', end = ' ')
		print()
	signatures = list()
	ttps = set()
	if file_report.get('signatures'):
		for sign in file_report.get('signatures'):
			s = dict()
			score = sign.get('score')
			if not score:
				s[sign.get('name')] = 0
			else:
				s[sign.get('name')] = score
			signatures.append(s)
			if sign.get('ttp'):
				for t in sign.get('ttp'):
					ttps.add(t)
	have = list()
	if file_report.get('extracted'):
		have.append('malware_config')
	if signatures:
		have.append('signatures')
	if file_report.get('targets'):
		for target in file_report.get('targets'):
			if target.get('iocs'):
				have.append('iocs')
				break
	if have:
		print('\thave: ', end='')
		for h in have:
			print(f'{console.highlight(h, bgColor=bgColor.RED, textColor=textColor.WHITE)}', end = ' ')
		print()
	if ttps:
		print('\tttps: ', end='')
		for t in ttps:
			print(f'{console.highlight(t, bgColor=bgColor.WHITE, textColor=textColor.BLACK)}', end = ' ')
		print()
	print('\tlink: ' + 'https://tria.ge/' + report_info.get('id'))
	if signatures:
		print('\tsignatures: ')
		for sign in signatures:
			if sign[list(sign.keys())[0]] < 5:
				print('\t\t' + list(sign.keys())[0])
			elif sign[list(sign.keys())[0]] < 8:
				print('\t\t', end='')
				print(f'{colors.WARNING}' + list(sign.keys())[0] + f'{colors.RESET}')
			else:
				print('\t\t', end='')
				print(f'{colors.ATTENTION}' + list(sign.keys())[0] + f'{colors.RESET}')
		print()
	return True


def triage_get_rules(hash):
	hashtype = 'md5'
	if len(hash) == 64:
		hashtype = 'sha256'
	report_info = triage.get_search(hashtype + ':' + hash)
	if not report_info:
		return
	report_info = report_info[0] # the most recent
	file_report = triage.get_sample_overview(report_info.get('id'))
	if not file_report:
		return
	yaras = set()
	suricatas = set()
	if file_report.get('signatures'):
		for sign in file_report.get('signatures'):
			if sign.get('label') and sign.get('label').startswith('suricata'):
				suricatas.add(sign.get('desc').replace('suricata: ', ''))
			if sign.get('indicators') and sign.get('indicators')[0].get('yara_rule'):
				yaras.add(sign.get('name'))
	if yaras or suricatas:
		print(f'rules from {console.highlight("triage", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}')
		if yaras:
			print('\t' + f'{console.highlight("yara", bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}')
			for yara in yaras:
				print('\t\t* ' + yara)
			print()
		if suricatas:
			print('\t' + f'{console.highlight("ids", bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}')
			for suri in suricatas:
				print('\t\t* ' + suri)
			print()

def triage_print_tags(hash):
	tags = triage_tags(hash)
	if tags:
		print(f'{console.highlight("triage", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}', end = ' ')
		print(': ', end=' ')
		for tag in tags:
			print(f'{console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}', end = ' ')
		print()

def triage_tags(hash):
	hashtype = 'md5'
	if len(hash) == 64:
		hashtype = 'sha256'
	report_info = triage.get_search(hashtype + ':' + hash)
	if not report_info:
		return
	report_info = report_info[0]
	file_report = triage.get_sample_overview(report_info.get('id'))
	if not file_report:
		return
	tags = list()
	tags.append('score:' + str(file_report.get('sample').get('score')))
	if file_report.get('analysis') and file_report.get('analysis').get('tags'):
		for tag in file_report.get('analysis').get('tags'):
			tags.append(tag)
	return tags

def triage_ioc_search(ioctype, ioc):
	report_info = triage.get_search(ioctype + ':' + ioc)
	if not report_info:
		return
	print(f'intel from {console.highlight("triage", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}\n')
	print('\t' + ioc, end = '')
	print('\treport_count: ' +  str(len(report_info)))
	tags = set()
	have = set()
	i = 0
	for report in report_info:
		have.add(report.get('kind'))
		ioc_report = triage.get_sample_overview(report.get('id'))
		if not ioc_report:
			return
		if ioc_report.get('analysis') and ioc_report.get('analysis').get('tags'):
			for tag in ioc_report.get('analysis').get('tags'):
				tags.add(tag)
	if tags:
		print('\ttags: ', end = '')
		tags = list(tags)
		for tag in tags[:10]:
			print(f'{console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}', end = ' ')
		if len(tags[:10]) > 10:
			print(f'{console.highlight("and more.", bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}', end = ' ')
		print()
	if have:
		print('\thave: ', end='')
		for h in have:
			print(f'{console.highlight(h, bgColor=bgColor.RED, textColor=textColor.WHITE)}', end = ' ')
		print()
	print('\tlink: ' + 'https://tria.ge/s?q=' + ioctype + '%3A' + ioc + '\n')

def triage_ip_search(ip):
	triage_ioc_search('ip', ip)

def triage_domain_search(domain):
	triage_ioc_search('domain', domain)

def triage_url_search(url):
	triage_ioc_search('url', url)

def triage_download_a_file(hash, path):
	hashtype = 'md5'
	if len(hash) == 64:
		hashtype = 'sha256'
	report_info = triage.get_search(hashtype + ':' + hash)
	if not report_info:
		return False
	return triage.download_a_file(hash, report_info[0].get('id'), path)

def triage_get_mitre(hash, banner=True):
	hashtype = 'md5'
	if len(hash) == 64:
		hashtype = 'sha256'
	report_info = triage.get_search(hashtype + ':' + hash)
	if not report_info:
		return False
	report_info = report_info[0] # the most recent
	file_report = triage.get_sample_overview(report_info.get('id'))
	if not file_report:
		return False
	ttps = set()
	for sign in file_report.get('signatures'):
		if sign.get('ttp'):
			for t in sign.get('ttp'):
				ttps.add(t)
	if ttps and banner:
		print(f'{console.highlight("triage", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}', end=' ')
	return list(ttps)

def triage_get_files_from_tag(tag, limit):
	tag_info = triage.get_search('family:' + tag)
	data = list()
	max_tags = 5
	headers = ['name + tags', 'type', 'size', 'first_seen', 'last_seen', 'sha256']
	if not tag_info:
		tag_info = triage.get_search('tag:' + tag)
		if not tag_info:
			return
	print('from ' + f'{console.highlight("triage", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}')
	for report_info in tag_info[:limit]:
		file_report = triage.get_sample_overview(report_info.get('id'))
		if not file_report:
			continue
		row = list()
		tags = ''
		if file_report.get('analysis') and file_report.get('analysis').get('tags'):
			tags = '\n'
			for tag in file_report.get('analysis').get('tags')[:max_tags]:
				tags = tags + ' ' + console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)
			if len(file_report.get('analysis').get('tags')) > max_tags:
				tags = tags + ' ' + console.highlight("+", bgColor=bgColor.YELLOW, textColor=textColor.BLACK)
		row.append(f'{colors.ATTENTION}' + pe.get_printable_name(report_info.get('filename'), file_report.get('targets')[0].get('md5'), file_report.get('targets')[0].get('sha256')) + f'{colors.RESET}' + tags)
		row.append(str(None))
		if file_report.get('sample'):
			row.append(pe.get_printable_size(file_report.get('sample').get('size')))
		else:
			row.append(str(None))
		row.append(str(report_info.get('submitted')).split('T')[0])
		row.append(str(None))
		row.append(str(file_report.get('sample').get('sha256')))
		data.append(row)
	print(tabulate(data, headers = headers, tablefmt = 'grid') + '\n')