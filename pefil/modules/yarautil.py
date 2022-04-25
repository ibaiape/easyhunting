import os
import sys
import yara
from py_console import console, bgColor, textColor
import warnings

blacklist = ['PECheck', 'PEiD']

def get_yara_file(path):
    root_dir = os.path.dirname(sys.modules['__main__'].__file__)
    return os.path.join(root_dir, 'utils/yara_rules/rules', path)

def get_yara_rules(filename):
    try:
        warnings.simplefilter("ignore")
        rules = yara.compile(filepaths={'AntiVM/DB': get_yara_file('antidebug_antivm_index.yar'),
                                        'Capabilities': get_yara_file('capabilities_index.yar'),
                                        'Crypto': get_yara_file('crypto_index.yar'),
                                        'CVE': get_yara_file('cve_rules_index.yar'),
                                        'Email': get_yara_file('email_index.yar'),
                                        'Exploit': get_yara_file('exploit_kits_index.yar'),
                                        'Document': get_yara_file('maldocs_index.yar'),
                                        'Malware': get_yara_file('malware_index.yar'),
                                        'Mobile': get_yara_file('mobile_malware_index.yar'),
                                        'Packers': get_yara_file('packers_index.yar'),
                                        'Webshell': get_yara_file('webshells_index.yar')})

        with open(filename, 'rb') as f:
            matches = rules.match(data=f.read())
        if matches:
            print(f'rules from {console.highlight("file", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}')
            print('\t' + f'{console.highlight("yara", bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}')
            counter = 0
            for x in matches:
                if x.tags:
                    blacklisted = 0
                    for tag in x.tags:
                        if tag in blacklist:
                            blacklisted += 1
                    if blacklisted == len(x.tags):
                        counter += 1
                        continue
                print('\t\t* ' + str(x.rule), end = '')
                print(' | ' + str(x.namespace), end = '')
                if x.tags:
                    print(' | ' + "".join(x.tags))
                else:
                    print()
            if counter != 0:
                print('\t\t  ' + str(counter) + ' yara rules have been blacklisted!')
                print()
    except Exception as e:
        print(e)
        pass