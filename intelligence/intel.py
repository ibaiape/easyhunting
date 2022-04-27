import os
import re
import sys
import requests
from tabulate import tabulate
from py_console import console, bgColor, textColor
from utils.colors import colors
import configparser

from intelligence import vt_intel
from intelligence import bazaar_intel
from intelligence import urlhaus_intel
from intelligence import threatfox_intel
from intelligence import alienvault_intel
from intelligence import triage_intel

import intelligence.apis.virustotal as virustotal
import intelligence.apis.bazaar as bazaar
import intelligence.apis.urlhaus as urlhaus
import intelligence.apis.threatfox as threatfox
import intelligence.apis.triage as triage

from pefil.modules import pe
from utils.attack_navigator.navigator_gen import create_matrix


def get_type(arg):
    ipv4 = r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
    url = r"(https?|ftp|telnet|ldap|file)://(([a-z0-9-._~!$&\'()*+,;=:]|%[0-9A-F]{2})*@)?(([a-z0-9-._~!$&\'()*+,;=]|%[0-9A-F]{2})*)(:(\d*))?(/(([^?\#\"<>\s]|%[0-9A-F]{2})*/?))?(\?(([a-z0-9-._~!$&'()*+,;=:/?@]|%[0-9A-F]{2})*))?(\#(([a-z0-9-._~!$&'()*+,;=:/?@]|%[0-9A-F]{2})*))?"
    domain = r"((?=[a-z0-9-]{1,63}\.)[a-z0-9]+(-[a-z0-9]+)*\.){1,126}[a-z]{2,63}"
    if os.path.isfile(arg):
        return 'file'
    if os.path.isdir(arg):
        return 'dir'
    if re.search(url, arg, re.IGNORECASE):
        return 'url'
    if re.search(domain, arg, re.IGNORECASE):
        return 'domain'
    if re.search(ipv4, arg, re.IGNORECASE):
        return 'ip'
    if len(arg) == 32:
        return 'md5'
    if len(arg) == 64:
        return 'sha256'
    print('\n' + arg + ' not found!')


def get_files_from_directory(dir):
    files = list()
    if not os.path.isabs(dir):
        dir = os.path.abspath('.') + "/" + dir
    os.chdir(dir)
    for f in os.listdir(dir):
        filename = str(f)
        if os.path.isdir(filename):
            files.extend(get_files_from_directory(filename))
            continue
        if not os.path.isfile(dir + '/' + filename):
            continue
        files.append(dir + '/' + filename)
    return files

def get_intel(target):
    print("'get threat info from intel sources'\n")
    targettype = get_type(target)
    if targettype == 'md5' or targettype == 'sha256':
        bazaar_intel.bazaar_file_search(target)
        urlhaus_intel.urlhaus_payload_search(target)
        threatfox_intel.threatfox_file_search(target)
        alienvault_intel.alienvault_file_search(target)
        triage_intel.triage_file_search(target)
        vt_intel.vt_file_search(target)
    elif targettype == 'url':
        urlhaus_intel.urlhaus_url_search(target)
        threatfox_intel.threatfox_ioc_search(target)
        alienvault_intel.alienvault_url_search(target)
        triage_intel.triage_url_search(target)
        vt_intel.vt_url_search(target)
    elif targettype == 'domain':
        urlhaus_intel.urlhaus_host_search(target)
        threatfox_intel.threatfox_ioc_search(target)
        alienvault_intel.alienvault_domain_search(target)
        triage_intel.triage_domain_search(target)
        vt_intel.vt_domain_search(target)
    elif targettype == 'ip':
        threatfox_intel.threatfox_ioc_search(target)
        alienvault_intel.alienvault_ip_search(target)
        triage_intel.triage_ip_search(target)
        vt_intel.vt_ip_search(target)
    elif targettype == 'file':
        sha256 = pe.get_hashes(target)['sha256']
        bazaar_intel.bazaar_file_search(sha256)
        urlhaus_intel.urlhaus_payload_search(sha256)
        threatfox_intel.threatfox_file_search(sha256)
        alienvault_intel.alienvault_file_search(sha256)
        triage_intel.triage_file_search(sha256)
        vt_intel.vt_file_search(sha256)
    elif targettype == 'dir':
        files = get_files_from_directory(target)
        for fil in files:
            sha256 = pe.get_hashes(fil)['sha256']
            print(os.path.basename(fil) + ' ' + sha256)
            bazaar_intel.bazaar_print_tags(sha256)
            urlhaus_intel.urlhaus_print_tags(sha256)
            threatfox_intel.threatfox_print_tags(sha256)
            alienvault_intel.alienvault_print_tags(sha256)
            triage_intel.triage_print_tags(sha256)
            vt_intel.vt_print_tags(sha256)
            print()

def get_intel_hits(sha256):
    hits = list()
    if bazaar.query_a_malware_sample(sha256):
        hits.append('bazaar')
    if urlhaus.query_payload_information(sha256):
        hits.append('urlhaus')
    if threatfox.search_for_IOCs_by_file_hash(sha256):
        hits.append('threatfox')
    if alienvault_intel.have_pulses(sha256):
        hits.append('alienvault')
    if triage.exist_file_report(sha256):
        hits.append('triage')
    if virustotal.get_a_file_report(sha256)[0]:
        hits.append('virustotal')
    return hits

def order_by_similar(fil):
    return list(fil.get('similar'))[0]

def get_similar(file):
    print("'get similar files from intel sources'\n")
    config = configparser.ConfigParser()
    config.read(os.path.dirname(sys.modules['__main__'].__file__) + '/config.ini')
    limit = config['limits']['similar']
    if not limit:
        limit = 5
    limit = int(limit)
    headers = ['name + tags', 'type', 'size', 'similar_hits', 'sha256']
    data = list()
    similars = dict()
    more_potencial_ones = dict()

    hashes = pe.get_hashes(file)
    version_strings = pe.get_version_strings(file)
    size = os.path.getsize(file)
    subject_cn = pe.get_subject_cn_signature(file)
     
    bazaar_intel.bazaar_similar_files(similars, hashes, limit, size, subject_cn)
    vt_intel.vt_similar_files(similars, hashes, limit, size, version_strings, subject_cn)
    
    for h in similars:
        fil = similars.get(h)
        if not more_potencial_ones.get(len(fil.get('similar'))):
            more_potencial_ones[len(fil.get('similar'))] = list()
        more_potencial_ones[len(fil.get('similar'))].append(fil)
    if len(more_potencial_ones.keys()) == 0:
        return
    for level in range(list(sorted(more_potencial_ones.keys(), reverse=True))[0], 0, -1):
        if not more_potencial_ones.get(level):
            continue
        for fil in sorted(more_potencial_ones.get(level), key=order_by_similar):
            row = list()
            name = f'{colors.ATTENTION}' + pe.get_printable_name(fil.get('filename'), fil.get('md5'), fil.get('sha256')) + f'{colors.RESET}'
            tags=''
            max_tags = 4
            intel_tags = dict()
            intel_tags['virustotal'] = vt_intel.vt_tags(fil.get('sha256'))
            intel_tags['bazaar'] = bazaar_intel.bazaar_tags(fil.get('sha256'))
            intel_tags['triage'] = triage_intel.triage_tags(fil.get('sha256'))
            for intel in intel_tags:
                if intel_tags.get(intel):
                    tags = tags + '\n' + console.highlight(intel, bgColor=bgColor.BLUE, textColor=textColor.WHITE) + ' '
                    for tag in list(intel_tags.get(intel))[:max_tags]:
                        tags = tags + ' ' + console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)
                    if len(list(intel_tags.get(intel))) > max_tags:
                        tags = tags + ' ' + console.highlight("+", bgColor=bgColor.YELLOW, textColor=textColor.BLACK)
            row.append(name + tags)
            row.append(str(fil.get('type')))
            row.append(pe.get_printable_size(fil.get('size')))
            similar = ''
            for s in fil.get('similar'):
                similar = similar + console.highlight(s, bgColor=bgColor.WHITE, textColor=textColor.BLACK) + '\n'
            row.append(similar)
            row.append(fil.get('sha256'))
            data.append(row)
    print(tabulate(data, headers = headers, tablefmt = 'grid'))

def vtintelligence_query(query):
    print("'virustotal intelligence'\n")
    config = configparser.ConfigParser()
    config.read(os.path.dirname(sys.modules['__main__'].__file__) + '/config.ini')
    limit = config['limits']['vtintelligence']
    if not limit:
        limit = 5
    limit = int(limit)
    vt_intel.vt_intelligence(query, limit)

def download_file(hash):
    print("'download file from the wild'\n")
    dirpath = "downloaded_samples/"
    if not os.path.exists(dirpath):
        os.mkdir(dirpath)
    if vt_intel.vt_download_a_file(hash, dirpath):
        print(f'the file has been succesfully downloaded from {console.highlight("virustotal", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}!')
        return
    if bazaar_intel.bazaar_download_a_file(hash, dirpath):
        print(f'the file has been succesfully downloaded from {console.highlight("bazaar", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}!')
        return
    if urlhaus_intel.urlhaus_download_a_file(hash, dirpath):
        print(f'the file has been succesfully downloaded from {console.highlight("urlhaus", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}!')
        return
    if triage_intel.triage_download_a_file(hash, dirpath):
        print(f'the file has been succesfully downloaded from {console.highlight("triage", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}!')
        return
    print('the file could not be downloaded from the wild!')

def get_technique_name_by_id(id):
    mitre_url = 'https://attack.mitre.org/'
    try:
        res = requests.get(mitre_url + 'techniques/' + id.replace('.', '/'))
        if res.status_code != 200:
            return ''
        html = res.text
        if html.find('<title>') != -1:
            return html[html.find('<title>') + 7 : html.find('</title>')].split(',')[0]
        elif html.find('url=/techniques/'): # old id case
            new_id = html[html.find('url=/techniques/') + 16 : html.find('"/>')]
            return get_technique_name_by_id(new_id) + ' (new_id: ' + new_id.replace('/', '.') + ')'
        else:
            return 'unknown'
    except requests.exceptions.RequestException:
        return ''

def get_mitre(target):
    print("'get mitre attack about a file from intel sources'\n")
    print('extracting techniques from...', end='')
    mitre = dict()
    targettype = get_type(target)
    if targettype == 'file':
        id = pe.get_hashes(target)['sha256']
        mitre['virustotal'] = vt_intel.vt_get_mitre(id)
        mitre['alienvault'] = alienvault_intel.alienvault_get_mitre(id)
        mitre['triage'] = triage_intel.triage_get_mitre(id)
        mitre['capa'] = pe.get_capa(target) #ctrl+c to cancel capa analysis
        target = id
    elif targettype == 'md5' or targettype == 'sha256':
        mitre['virustotal'] = vt_intel.vt_get_mitre(target)
        mitre['alienvault'] = alienvault_intel.alienvault_get_mitre(target)
        mitre['triage'] = triage_intel.triage_get_mitre(target)
    print('\n')
    if mitre:
        for intel in mitre.keys():
            if mitre.get(intel):
                print(f'{console.highlight(intel, bgColor=bgColor.BLUE, textColor=textColor.WHITE)}')
                for t in mitre.get(intel):
                    print('\t', end='')
                    print(f'{console.highlight(t, bgColor=bgColor.WHITE, textColor=textColor.BLACK)}', end = '')
                    print(': ' + get_technique_name_by_id(t))
                print()
        print()
    create_matrix(target, mitre)

def get_intel_rules(hash):
    bazaar_intel.bazaar_get_rules(hash)
    alienvault_intel.alienvault_get_rules(hash)
    triage_intel.triage_get_rules(hash)
    vt_intel.vt_get_rules(hash)

def get_files_from_tag(tag):
    config = configparser.ConfigParser()
    config.read(os.path.dirname(sys.modules['__main__'].__file__) + '/config.ini')
    limit = config['limits']['tags']
    if not limit:
        limit = 5
    limit = int(limit)
    print("'get files from tag: " + f"{console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}" + "'\n")
    bazaar_intel.bazaar_get_files_from_tag(tag, limit)
    triage_intel.triage_get_files_from_tag(tag, limit)
    vt_intel.vt_get_files_from_tag(tag, limit)
    
