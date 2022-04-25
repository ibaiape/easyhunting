import json
from py_console import console, bgColor, textColor
from utils.colors import colors

from intelligence.apis import threatfox
from pefil.modules import pe

def threatfox_ioc_search(ioc):
    ioc_report = threatfox.search_an_IOC(ioc)
    if not ioc_report:
        return
    print(f'intel from {console.highlight("threatfox", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}\n')
    print(f'\t{colors.ATTENTION}' + str(ioc_report.get('ioc')) + f'{colors.RESET}', end = '')
    print('\tfs: ' + ioc_report.get('first_seen') + '\tmalware_samples: ' +  str(len(ioc_report.get('malware_samples'))))
    additional_tags = set()
    if ioc_report.get('threat_type'):
        additional_tags.add(ioc_report.get('threat_type'))
    if ioc_report.get('malware'):
        additional_tags.add(ioc_report.get('malware'))
    if ioc_report.get('tags') or additional_tags:
        print('\ttags: ', end = '')
        for tag in ioc_report.get('tags') + list(additional_tags):
            print(f'{console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}', end = ' ')
        print()
    print('\tlink: ' + 'https://threatfox.abuse.ch/browse.php?search=ioc%3A' + ioc + '\n')
    


def threatfox_file_search(hash, banner=True):
    file_report = threatfox.search_for_IOCs_by_file_hash(hash)
    if not file_report:
        return
    if banner:
        print(f'intel from {console.highlight("threatfox", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}\n')
    print(f'\t{colors.ATTENTION}' + hash + f'{colors.RESET}', end = '')
    print('\tiocs: ' +  str(len(file_report)))
    tags = set()
    iocs = set()
    for ioc in file_report:
        if ioc.get('threat_type'):
            tags.add(ioc.get('threat_type'))
        if ioc.get('malware'):
            tags.add(ioc.get('malware'))
        if ioc.get('tags'):
            for tag in ioc.get('tags'):
                tags.add(tag)
        if ioc.get('ioc'):
            iocs.add(ioc.get('ioc'))
    if tags:
        print('\ttags: ', end = '')
        for tag in tags:
            print(f'{console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}', end = ' ')
        print()

    if iocs:
        print('\tiocs: ')
        for ioc in iocs:
            print('\t\t' + ioc)
        print()
    #print('\tlink: ' + 'https://threatfox.abuse.ch/ioc/' + ioc_report.get('id'))


def threatfox_print_tags(hash):
    file_report = threatfox.search_for_IOCs_by_file_hash(hash)
    if not file_report:
        return
    tags = set()
    for ioc in file_report:
        if ioc.get('threat_type'):
            tags.add(ioc.get('threat_type'))
        if ioc.get('malware'):
            tags.add(ioc.get('malware'))
        if ioc.get('tags'):
            for tag in ioc.get('tags'):
                tags.add(tag)
    if tags:
        print(f'{console.highlight("threatfox", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}', end = ' ')
        print(': ', end=' ')
        for tag in tags:
            print(f'{console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}', end = ' ')
        print()