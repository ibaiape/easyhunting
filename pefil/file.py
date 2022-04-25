import os
import magic
from py_console import console, bgColor, textColor

from pefil.modules import pe
from intelligence import intel
from pefil.modules.yarautil import get_yara_rules

def simple_report(filename):
    print("'simple file report'\n") 
    print('name: ' + filename)
    print('type: ' + magic.from_file(filename))
    print('size: ' + pe.get_printable_size(os.path.getsize(filename)))
    if pe.is_pe(filename):
        peid_result = pe.get_packer(filename)
        if peid_result:
            print('compiler/packer: ' + str(peid_result) + ' (by peid)')
    print()
    hashes = pe.get_hashes(filename)
    for hash in hashes:
        if hashes.get(hash):
            print(hash + ': '+ str(hashes[hash]))
    print()
    if pe.is_pe(filename):
        liefpe = pe.load_pe(filename)
        pe.get_version(liefpe)
        pe.get_digital_signature(liefpe)
        pe.get_sections(liefpe)
        pe.get_imports(liefpe)
        pe.get_exports(liefpe)
    print('intelligence sources detected: ', end='')
    intels = intel.get_intel_hits(hashes['sha256'])
    if intels:
        console.setShowTimeDefault(False)
        for i in intels:
            print(f'{console.highlight(i, bgColor=bgColor.BLUE, textColor=textColor.WHITE)}', end = ' ')
        print()
    else:
        print('None')

def dis_ep(filename):
    print("'disassemble the file entrypoint'\n")
    if not pe.is_pe(filename):
        print('it is not PE file')
        exit()
    pe.disassemble_ep(filename)

def dis_sc(filename):
    print("'disassemble a x86 shellcode'\n")
    if not os.path.isfile(filename):
        print('it is not a file')
        exit()
    if pe.is_pe(filename):
        print('it is a PE file')
        exit()
    pe.disassemble_sc(filename)

def dis_sc64(filename):
    print("'disassemble a x64 shellcode'\n")
    if not os.path.isfile(filename):
        print('it is not a file')
        exit()
    if pe.is_pe(filename):
        print('it is a PE file')
        exit()
    pe.disassemble_sc64(filename)

def get_rules(filename):
    print("'get yara, sigma and ids rules from a file'\n")
    if not os.path.isfile(filename):
        print('it is not a file')
        exit()
    if pe.is_pe(filename):
        get_yara_rules(filename)
    intel.get_intel_rules(pe.get_hashes(filename)['sha256'])