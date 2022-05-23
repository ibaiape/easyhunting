import json
from py_console import console, bgColor, textColor
from utils.colors import colors

from intelligence.apis import urlhaus
from pefil.modules import pe


def urlhaus_url_search(url):
    url_report = urlhaus.query_url_information(url)
    if not url_report:
        return
    print(f'intel from {console.highlight("urlhaus", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}\n')
    print(f'\t{colors.ATTENTION}' + url + f'{colors.RESET}', end = '')
    print('\tfs: ' + url_report.get('date_added') + '\tstatus: ' + url_report.get('url_status'), end='')
    print('\tls: ' + url_report.get('last_online') if url_report.get('url_status') == 'offline' else '')
    additional_tags = set()
    if url_report.get('threat'):
        additional_tags.add(url_report.get('threat'))
    if url_report.get('blacklists'):
        for bname in url_report.get('blacklists'):
            if url_report.get('blacklists').get(bname) != 'not listed':
                if bname == 'surbl':
                    additional_tags.add('surbl_listed')
                else:
                    additional_tags.add(url_report.get('blacklists').get(bname))
    if url_report.get('tags') or additional_tags:
        print('\ttags: ', end = '')
        for tag in url_report.get('tags') + list(additional_tags):
            print(f'{console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}', end = ' ')
        print()
    if url_report.get('payloads'):
        payload_signatures = set()
        for payload in url_report.get('payloads'):
            if payload.get('signature'):
                payload_signatures.add(payload.get('signature'))
        print(f'\tpayload: ', end='')
        i = 0
        if payload_signatures:
            for signature in payload_signatures:
                print(f'{console.highlight(signature, bgColor=bgColor.RED, textColor=textColor.WHITE)}', end = ' ')
                i += 1
                if i == 4:
                    print(f'{console.highlight("and more.", bgColor=bgColor.RED, textColor=textColor.WHITE)}', end = ' ')
                    break
            print()
        else:
            print(f'{console.highlight("unknown", bgColor=bgColor.RED, textColor=textColor.WHITE)}')
    print('\tlink: ' + url_report.get('urlhaus_reference') + '\n')


def urlhaus_host_search(host):
    host_report = urlhaus.query_host_information(host)
    if not host_report:
        return
    print(f'intel from {console.highlight("urlhaus", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}\n')
    print(f'\t{colors.ATTENTION}' + host + f'{colors.RESET}', end = '')
    print('\tfs: ' + host_report.get('firstseen') + '\turlcount: ' + str(host_report.get('url_count')))
    tags = set()
    if host_report.get('blacklists'):
        for bname in host_report.get('blacklists'):
            if host_report.get('blacklists').get(bname) != 'not listed':
                if bname == 'surbl':
                    tags.add('surbl_listed')
                else:
                    tags.add(host_report.get('blacklists').get(bname))
    i = 0
    for url in host_report.get('urls'):
        if url.get('tags'):
            for utag in url.get('tags'):
                tags.add(utag)
            i += 1
        if i == 14 and int(host_report.get('url_count')) > 15:
            tags = list(tags)
            tags.append('and_more.')
            break
    if tags:
        print('\ttags: ', end = '')
        for tag in tags:
            print(f'{console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}', end = ' ')
        print()
    print('\tlink: ' + host_report.get('urlhaus_reference') + '\n')


def urlhaus_payload_search(hash, banner=True):
    file_report = urlhaus.query_payload_information(hash)
    if not file_report:
        return
    if banner:
        print(f'intel from {console.highlight("urlhaus", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}\n')
    print(f'\t{colors.ATTENTION}' + pe.get_printable_name(file_report.get('urls')[0].get('filename'), file_report.get('md5_hash'), file_report.get('sha256_hash')) + f'{colors.RESET}', end = '')
    print('\t' + pe.get_printable_size(int(file_report.get('file_size'))) + '\t' + 'fs: ' + str(file_report.get('firstseen')) + '\turlcount: ' + str(file_report.get('url_count')) + '\t' + str(file_report.get('sha256_hash')))
    tags = set()
    if file_report.get('file_type'):
        tags.add(file_report.get('file_type'))
    if file_report.get('signature'):
        tags.add(file_report.get('signature'))
    if tags:
        print('\ttags: ', end = '')
        for tag in tags:
            print(f'{console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}', end = ' ')
        print()
    print('\tlink: ' + 'https://urlhaus.abuse.ch/browse.php?search=' + hash + '\n')

def urlhaus_print_tags(hash):
    file_report = urlhaus.query_payload_information(hash)
    if not file_report:
        return
    tags = set()
    if file_report.get('file_type'):
        tags.add(file_report.get('file_type'))
    if file_report.get('signature'):
        tags.add(file_report.get('signature'))
    if tags:
        print(f'{console.highlight("urlhaus", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}', end = ' ')
        print(': ', end=' ')
        for tag in tags:
            print(f'{console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}', end = ' ')
        print()

def urlhaus_tags(hash):
    file_report = urlhaus.query_payload_information(hash)
    if not file_report:
        return
    tags = set()
    if file_report.get('file_type'):
        tags.add(file_report.get('file_type'))
    if file_report.get('signature'):
        tags.add(file_report.get('signature'))
    return tags


def urlhaus_download_a_file(sha256, path):
	return urlhaus.download_malware_sample(sha256, path)