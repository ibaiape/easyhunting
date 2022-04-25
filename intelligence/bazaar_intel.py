import json
from py_console import console, bgColor, textColor
from utils.colors import colors
from tabulate import tabulate

from intelligence.apis import bazaar
from pefil.modules import pe


def bazaar_file_search(hash, banner=True):
    file_report = bazaar.query_a_malware_sample(hash)
    if not file_report:
        return False
    if banner:
        print(f'intel from {console.highlight("bazaar", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}\n')
    print(f'\t{colors.ATTENTION}' + pe.get_printable_name(file_report.get('file_name'), file_report.get('md5_hash'), file_report.get('sha256_hash')) + f'{colors.RESET}', end = '')
    print('\t' + pe.get_printable_size(file_report.get('file_size')) + '\t' + 'fs: ' + str(file_report.get('first_seen')) + '\t' + file_report.get('sha256_hash'))
    if file_report.get('tags'):
        print('\ttags: ', end = '')
        for tag in file_report.get('tags'):
            print(f'{console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}', end = ' ')
        if file_report.get('delivery_method'):
            delivery_method = file_report.get('delivery_method') + '_delivery'
            print(f'{console.highlight(delivery_method, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}', end = ' ')
        if file_report.get('ole_information'):
            print(f'{console.highlight("ole_info", bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}', end = ' ')
        print()

    have = list()
    if file_report.get('yara_rules'):
        have.append('yara')
    if file_report.get('file_information'):
        have.append('context_info')
    if file_report.get('comments'):
        have.append('comments')
    if have:
        print('\thave: ', end='')
        for h in have:
            print(f'{console.highlight(h, bgColor=bgColor.RED, textColor=textColor.WHITE)}', end = ' ')
        print()
    if file_report.get('vendor_intel'):
        print('\tintel: ', end = '')
        for intel in file_report.get('vendor_intel'):
            print(f'{console.highlight(intel, bgColor=bgColor.BLUE, textColor=textColor.WHITE)}', end = ' ')
        print()
    print('\tlink: ' + 'https://bazaar.abuse.ch/sample/' + file_report.get('sha256_hash') + '\n')
    return True


def bazaar_print_tags(hash):
    tags = bazaar_tags(hash)
    if tags:
        print(f'{console.highlight("bazaar", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}', end = ' ')
        print(': ', end=' ')
        for tag in tags:
            print(f'{console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}', end = ' ')
        print()

def bazaar_tags(hash):
    file_report = bazaar.query_a_malware_sample(hash)
    if not file_report:
        return
    tags = list()
    if file_report.get('tags'):
        for tag in file_report.get('tags'):
            tags.append(tag)
    if file_report.get('delivery_method'):
        delivery_method = file_report.get('delivery_method') + '_delivery'
        tags.append(delivery_method)
    if file_report.get('ole_information'):
        tags.append(file_report.get('ole_information'))
    return tags

def bazaar_similar_files(similars, hashes, limit, size, subject_cn):
    similar_hashes = ['imphash', 'tlsh', 'dhash']
    for hash in similar_hashes:
        files = list()
        if not hashes.get(hash):
            continue
        if hash == 'imphash':
            files = bazaar_imphash_similar(hashes[hash], limit)
        elif hash == 'tlsh':
            files = bazaar_tlsh_similar(hashes[hash], limit)
        elif hash == 'dhash':
            files = bazaar_dhash_similar(hashes[hash], limit)
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
                if not update.get('filename'):
                    update['filename'] = fil.get('filename')
                update['similar'].add(hash)
                if (fil.get('size') >= size * 0.95) and (fil.get('size') <= size * 1.05):
                    update['similar'].add('size')
                similars[fil.get('sha256')] = update
    if subject_cn:
        files = bazaar_subject_cn_sign(subject_cn, limit)
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
                if not update.get('filename'):
                    update['filename'] = fil.get('filename')
                update['similar'].add('sign')
                if (fil.get('size') >= size * 0.95) and (fil.get('size') <= size * 1.05):
                    update['similar'].add('size')
                similars[fil.get('sha256')] = update

def bazaar_imphash_similar(imphash, limit):
    imphash_similar = bazaar.query_imphash(imphash, limit)
    files_result = list()
    if imphash_similar:
        for similar in imphash_similar:
            fil = dict()
            fil['sha256'] = similar.get('sha256_hash')
            fil['md5'] = similar.get('md5_hash')
            fil['filetype'] = similar.get('file_type')
            fil['filename'] = similar.get('file_name')
            fil['size'] = similar.get('file_size')
            fil['tags'] = similar.get('tags')
            files_result.append(fil)
    return files_result

def bazaar_tlsh_similar(tlsh, limit):
    tlsh_similar = bazaar.query_tlsh(tlsh, limit)
    files_result = list()
    if tlsh_similar:
        for similar in tlsh_similar:
            fil = dict()
            fil['sha256'] = similar.get('sha256_hash')
            fil['md5'] = similar.get('md5_hash')
            fil['filetype'] = similar.get('file_type')
            fil['size'] = similar.get('file_size')
            fil['filename'] = similar.get('file_name')
            fil['tags'] = similar.get('tags')
            files_result.append(fil)
    return files_result

def bazaar_dhash_similar(dhash, limit):
    dhash_similar = bazaar.query_icon_dhash(dhash, limit)
    files_result = list()
    if not dhash_similar:
        return files_result
    for similar in dhash_similar:
        fil = dict()
        fil['sha256'] = similar.get('sha256_hash')
        fil['md5'] = similar.get('md5_hash')
        fil['filetype'] = similar.get('file_type')
        fil['size'] = similar.get('file_size')
        fil['filename'] = similar.get('file_name')
        fil['tags'] = similar.get('tags')
        files_result.append(fil)
    return files_result

def bazaar_subject_cn_sign(subject_cn, limit):
    cn_similar = bazaar.subject_cn_sign(subject_cn, limit)
    files_result = list()
    if not cn_similar:
        return files_result
    for similar in cn_similar:
        fil = dict()
        fil['sha256'] = similar.get('sha256_hash')
        fil['md5'] = similar.get('md5_hash')
        fil['filetype'] = similar.get('file_type')
        fil['size'] = similar.get('file_size')
        fil['filename'] = similar.get('file_name')
        fil['tags'] = similar.get('tags')
        files_result.append(fil)
    return files_result

def bazaar_download_a_file(sha256, path):
	return bazaar.download_a_malware_sample(sha256, path)

def bazaar_get_rules(hash):
    file_report = bazaar.query_a_malware_sample(hash)
    if not file_report:
        return
    if file_report.get('yara_rules'):
        print(f'rules from {console.highlight("bazaar", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}')
        print('\t' + f'{console.highlight("yara", bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}')
        for yara in file_report.get('yara_rules'):
            if yara.get('description'):
                print('\t\t* ' + yara.get('description'))
            else:
                print('\t\t* ' + yara.get('rule_name'))
        print()

def bazaar_get_files_from_tag(tag, limit):
    tag_report = bazaar.query_tag(tag, limit)
    headers = ['name + tags', 'type', 'size', 'first_seen', 'last_seen', 'sha256']
    data = list()
    max_tags = 5
    if not tag_report:
        return
    print('from ' + f'{console.highlight("bazaar", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}')
    for fil in tag_report:
        row = list()
        tags=''
        if fil.get('tags'):
            tags = '\n'
            for tag in fil.get('tags')[:max_tags]:
                 tags = tags + ' ' + console.highlight(tag, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)
            if fil.get('delivery_method'):
                delivery_method = fil.get('delivery_method') + '_delivery'
                tags = tags + ' ' + console.highlight(delivery_method, bgColor=bgColor.YELLOW, textColor=textColor.BLACK)
            if len(fil.get('tags')) > max_tags:
                tags = tags + ' ' + console.highlight("+", bgColor=bgColor.YELLOW, textColor=textColor.BLACK)
        row.append(f'{colors.ATTENTION}' + pe.get_printable_name(fil.get('file_name'), fil.get('md5_hash'), fil.get('sha256_hash')) + f'{colors.RESET}' + tags)
        row.append(str(fil.get('file_type')))
        row.append(pe.get_printable_size(fil.get('file_size')))
        row.append(str(fil.get('first_seen')).split(' ')[0])
        row.append(str(fil.get('last_seen')).split(' ')[0])
        row.append(str(fil.get('sha256_hash')))
        data.append(row)
    print(tabulate(data, headers = headers, tablefmt = 'grid') + '\n')