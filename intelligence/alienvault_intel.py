import json
from py_console import console, bgColor, textColor
from utils.colors import colors

from intelligence.apis import alienvault
from pefil.modules import pe

def alienvault_ip_search(ip):
	ip_report = alienvault.ip_search(ip)
	if not ip_report or ip_report.get('general') == None or (ip_report.get('general').get('pulse_info') and ip_report.get('general').get('pulse_info').get('count') == 0):
		return False
	print(f'intel from {console.highlight("alienvault", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}\n')
	have = list()
	pulses = list()
	tags = set()
	ttps = set()
	status = 'online'
	if ip_report.get('general').get('pulse_info') and ip_report.get('general').get('pulse_info').get('count') > 0:
		for pulse in ip_report.get('general').get('pulse_info').get('pulses'):
			pulses.append(pulse.get('name'))
			if pulse.get('adversary'):
				tags.add(pulse.get('adversary'))
			if pulse.get('malware_families'):
				for family in pulse.get('malware_families'):
					tags.add(family.get('display_name'))
			if pulse.get('attack_ids'):
				for attack in pulse.get('attack_ids'):
					tags.add(attack.get('id'))
		have.append('pulses')
		if ip_report.get('general').get('pulse_info').get('pulses')[0] == 0:
			status = 'offline'
	tags.add(status)
	if ip_report.get('malware').get('count') > 0:
		have.append('related_malware')
	if ip_report.get('url_list').get('actual_size') > 0:
		have.append('related_urls')
	if ip_report.get('passive_dns').get('count') > 0:
		have.append('passive_dns')
	print('\t' + ip if len(pulses) == 0 else f'\t{colors.ATTENTION}' + ip + f'{colors.RESET}')
	if tags:
		print('\ttags: ', end = '')
		for tag in tags:
			print(f'{console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}', end = ' ')
		print()
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
	if pulses:
		print('\tpulses: ')
		for pulse in pulses:
			print('\t\t' + pulse)
	print('\tlink: ' + 'https://otx.alienvault.com/indicator/ip/' + ip + '\n')


def alienvault_domain_search(domain):
	domain_report = alienvault.domain_search(domain)
	if not domain_report or domain_report.get('general') == None or (domain_report.get('general').get('pulse_info') and domain_report.get('general').get('pulse_info').get('count') == 0):
		return False
	print(f'intel from {console.highlight("alienvault", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}\n')
	have = list()
	pulses = list()
	tags = set()
	ttps = set()
	status = 'online'
	if domain_report.get('general').get('pulse_info') and domain_report.get('general').get('pulse_info').get('count') > 0:
		for pulse in domain_report.get('general').get('pulse_info').get('pulses'):
			pulses.append(pulse.get('name'))
			if pulse.get('adversary'):
				tags.add(pulse.get('adversary'))
			if pulse.get('malware_families'):
				for family in pulse.get('malware_families'):
					tags.add(family.get('display_name'))
			if pulse.get('attack_ids'):
				for attack in pulse.get('attack_ids'):
					ttps.add(attack.get('id'))
		have.append('pulses')
		if domain_report.get('general').get('pulse_info').get('pulses')[0] == 0:
			status = 'offline'
	tags.add(status)
	if domain_report.get('malware').get('count') > 0:
		have.append('malware')
	if domain_report.get('url_list').get('actual_size') > 0:
		have.append('related_urls')
	if domain_report.get('passive_dns').get('count') > 0:
		have.append('passive_dns')
	print('\t' + domain if len(pulses) == 0 else f'\t{colors.ATTENTION}' + domain + f'{colors.RESET}')
	if tags:
		print('\ttags: ', end = '')
		for tag in tags:
			print(f'{console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}', end = ' ')
		print()
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
	if pulses:
		print('\tpulses: ')
		for pulse in pulses:
			print('\t\t' + pulse)
	print('\tlink: ' + 'https://otx.alienvault.com/indicator/domain/' + domain + '\n')

def alienvault_url_search(url):
	url_report = alienvault.url_search(url)
	if not url_report or url_report.get('general') == None or (url_report.get('general') and url_report.get('general').get('pulse_info') and url_report.get('general').get('pulse_info').get('count') == 0):
		return False
	print(f'intel from {console.highlight("alienvault", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}\n')
	have = list()
	pulses = list()
	tags = set()
	ttps = set()
	status = 'online'
	if url_report.get('general').get('pulse_info') and url_report.get('general').get('pulse_info').get('count') > 0:
		for pulse in url_report.get('general').get('pulse_info').get('pulses'):
			pulses.append(pulse.get('name'))
			if pulse.get('adversary'):
				tags.add(pulse.get('adversary'))
			if pulse.get('malware_families'):
				for family in pulse.get('malware_families'):
					tags.add(family.get('display_name'))
			if pulse.get('attack_ids'):
				for attack in pulse.get('attack_ids'):
					ttps.add(attack.get('id'))
		have.append('pulses')
		if url_report.get('general').get('pulse_info').get('pulses')[0] == 0:
			status = 'offline'
	tags.add(status)
	if len(url_report.get('url_list')) > 0:
		have.append('related_urls')
	print('\t' + url if len(pulses) == 0 else f'\t{colors.ATTENTION}' + url + f'{colors.RESET}')
	if tags:
		print('\ttags: ', end = '')
		for tag in tags:
			print(f'{console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}', end = ' ')
		print()
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
	if pulses:
		print('\tpulses: ')
		for pulse in pulses:
			print('\t\t' + pulse)
	print('\tlink: ' + 'https://otx.alienvault.com/indicator/url/' + url + '\n')

def have_pulses(hash):
	file_report = alienvault.file_search(hash)
	if not file_report or file_report.get('general') == None or (file_report.get('general').get('pulse_info') and file_report.get('general').get('pulse_info').get('count') == 0):
		return False
	return True

def alienvault_file_search(hash, banner=True):
	file_report = alienvault.file_search(hash)
	if not file_report or file_report.get('general') == None or (file_report.get('general') and file_report.get('general').get('pulse_info') and file_report.get('general').get('pulse_info').get('count') == 0):
		return False
	if banner:
		print(f'intel from {console.highlight("alienvault", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}\n')
	have = list()
	pulses = list()
	tags = set()
	ttps = set()
	pulse_related_tags = False
	cuckoo_signatures = list()
	references = False
	for pulse in file_report.get('general').get('pulse_info').get('pulses'):
		pulses.append(pulse.get('name'))
		if pulse.get('tags'):
			pulse_related_tags = True
		if pulse.get('adversary'):
			tags.add(pulse.get('adversary'))
		if pulse.get('malware_families'):
			for family in pulse.get('malware_families'):
				tags.add(family.get('display_name'))
		if pulse.get('attack_ids'):
			for attack in pulse.get('attack_ids'):
				ttps.add(attack.get('id'))
		if pulse.get('references'):
			references = True
	have.append('pulses')
	if file_report.get('analysis') and file_report.get('analysis').get('analysis') and file_report.get('analysis').get('analysis').get('plugins'):
		if file_report.get('analysis').get('analysis').get('plugins').get('cuckoo') and file_report.get('analysis').get('analysis').get('plugins').get('cuckoo').get('result'):
			if file_report.get('analysis').get('analysis').get('plugins').get('cuckoo').get('result').get('signatures'):
				have.append('cuckoo')
				for sign in file_report.get('analysis').get('analysis').get('plugins').get('cuckoo').get('result').get('signatures'):
					s = dict()
					s[sign.get('name')] = sign.get('severity')
					cuckoo_signatures.insert(0, s)
					if sign.get('ttp'):
						for ttp in sign.get('ttp'):
							ttps.add(ttp)
			if file_report.get('analysis').get('analysis').get('plugins').get('cuckoo').get('result').get('suricata') and file_report.get('analysis').get('analysis').get('plugins').get('cuckoo').get('result').get('suricata').get('rules'):
				have.append('suricatas')
		if file_report.get('analysis').get('analysis').get('plugins').get('yarad') and file_report.get('analysis').get('analysis').get('plugins').get('yarad').get('results') and file_report.get('analysis').get('analysis').get('plugins').get('yarad').get('results').get('detection'):
			have.append('yaras')
	if pulse_related_tags:
		have.append('pulse_related_tags')
	if references:
		have.append('references')
	print(f'\t{colors.ATTENTION}' + hash + f'{colors.RESET}')
	tags = list(tags)
	if file_report.get('analysis') and file_report.get('analysis').get('analysis') and file_report.get('analysis').get('analysis').get('info') and file_report.get('analysis').get('analysis').get('info').get('results') and file_report.get('analysis').get('analysis').get('info').get('results').get('file_class'):
		tags.insert(0, file_report.get('analysis').get('analysis').get('info').get('results').get('file_class'))
	if tags:
		print('\ttags: ', end = '')
		for tag in tags:
			print(f'{console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}', end = ' ')
		print()
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
	if cuckoo_signatures:
		print('\tcuckoo: ', end='')
		for sign in cuckoo_signatures:
			if sign[list(sign.keys())[0]] < 2:
				#print(list(sign.keys())[0])
				pass
			elif sign[list(sign.keys())[0]] < 3:
				print(f'{colors.WARNING}' + list(sign.keys())[0] + f'{colors.RESET}', end = ' ')
			else:
				print(f'{colors.ATTENTION}' + list(sign.keys())[0] + f'{colors.RESET}', end = ' ')
		print()
	print('\tlink: ' + 'https://otx.alienvault.com/indicator/file/' + hash)
	if pulses:
		print('\tpulses: ')
		for pulse in pulses:
			print('\t\t' + pulse)
		print()
	return True


def alienvault_print_tags(hash):
	file_report = alienvault.file_search(hash)
	if not file_report or (file_report.get('general').get('pulse_info') and file_report.get('general').get('pulse_info').get('count') == 0):
		return
	tags = set()
	for pulse in file_report.get('general').get('pulse_info').get('pulses'):
		if pulse.get('adversary'):
			tags.add(pulse.get('adversary'))
		if pulse.get('malware_families'):
			for family in pulse.get('malware_families'):
				tags.add(family.get('display_name'))
	tags = list(tags)
	if file_report.get('analysis') and file_report.get('analysis').get('analysis') and file_report.get('analysis').get('analysis').get('info') and file_report.get('analysis').get('analysis').get('info').get('results') and file_report.get('analysis').get('analysis').get('info').get('results').get('file_class'):
		tags.insert(0, file_report.get('analysis').get('analysis').get('info').get('results').get('file_class'))
	if tags:
		print(f'{console.highlight("alienvault", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}', end = ' ')
		print(': ', end=' ')
		for tag in tags:
			print(f'{console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}', end = ' ')
		print()


def alienvault_get_mitre(hash, banner=True):
	file_report = alienvault.file_search(hash)
	if not file_report or file_report.get('general') == None or (file_report.get('general').get('pulse_info') and file_report.get('general').get('pulse_info').get('count') == 0):
		return False
	ttps = set()
	for pulse in file_report.get('general').get('pulse_info').get('pulses'):
		if pulse.get('attack_ids'):
			for attack in pulse.get('attack_ids'):
				ttps.add(attack.get('id'))
	if file_report.get('analysis') and file_report.get('analysis').get('analysis') and file_report.get('analysis').get('analysis').get('plugins') and file_report.get('analysis').get('analysis').get('plugins').get('cuckoo') and file_report.get('analysis').get('analysis').get('plugins').get('cuckoo').get('result') and file_report.get('analysis').get('analysis').get('plugins').get('cuckoo').get('result').get('signatures'):
		for sign in file_report.get('analysis').get('analysis').get('plugins').get('cuckoo').get('result').get('signatures'):
			if sign.get('ttp'):
				for ttp in sign.get('ttp'):
					ttps.add(ttp)
	if ttps and banner:
		print(f'{console.highlight("alienvault", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}', end=' ')
	return list(ttps)

def alienvault_get_rules(hash):
	file_report = alienvault.file_search(hash)
	if not file_report or file_report.get('general') == None or (file_report.get('general').get('pulse_info') and file_report.get('general').get('pulse_info').get('count') == 0):
		return False
	yaras = set()
	suricatas = set()
	if file_report.get('analysis') and file_report.get('analysis').get('analysis') and file_report.get('analysis').get('analysis').get('plugins'):
		if file_report.get('analysis').get('analysis').get('plugins').get('cuckoo') and file_report.get('analysis').get('analysis').get('plugins').get('cuckoo').get('result'):
			if file_report.get('analysis').get('analysis').get('plugins').get('cuckoo').get('result').get('suricata') and file_report.get('analysis').get('analysis').get('plugins').get('cuckoo').get('result').get('suricata').get('rules'):
				for rule in file_report.get('analysis').get('analysis').get('plugins').get('cuckoo').get('result').get('suricata').get('rules'):
					if rule.get('name'):
						suricatas.add(rule.get('name'))
		if file_report.get('analysis').get('analysis').get('plugins').get('yarad') and file_report.get('analysis').get('analysis').get('plugins').get('yarad').get('results') and file_report.get('analysis').get('analysis').get('plugins').get('yarad').get('results').get('detection'):
			for rule in file_report.get('analysis').get('analysis').get('plugins').get('yarad').get('results').get('detection'):
				if rule.get('rule_name'):
					yaras.add(rule.get('rule_name'))
	if yaras or suricatas:
		print(f'rules from {console.highlight("alienvault", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}')
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
