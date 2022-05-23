import os
import platform
import re
import magic
import lief
import pefile
import peutils
import hashlib
from iced_x86 import *
from py_console import console, bgColor, textColor
from tabulate import tabulate

from pefil.modules import pe
from utils.colors import colors
from utils import malapi
from pefil.modules.capautil import run_capa

lief.logging.disable()

def is_pe(file):
    if not magic.from_file(file).startswith('PE') and not magic.from_file(file).startswith('MS-DOS'):
        return False
    return True

def load_pe(filename):
    return lief.parse(filename)

def get_version(pe):
    try:
        if not (pe.has_resources and pe.resources_manager.has_version and pe.resources_manager.version.has_string_file_info):
            return None
        else:
            print('metadata') 
            print(str(pe.resources_manager.version.string_file_info).split('Items:')[1])
    except:
        pass

def get_version_strings(file):
    try:
        targets = ['InternalName', 'OriginalFilename', 'CompanyName', 'FileDescription'] # order by the most accurate (for me)
        version_strings = dict()
        fil = pe.load_pe(file)
        if not (fil.has_resources and fil.resources_manager.has_version and fil.resources_manager.version.has_string_file_info):
            return None
        else:
            version = fil.resources_manager.version.string_file_info.langcode_items[0].items
            for target in targets:
                if version.get(target):
                    version_strings[target] = version.get(target).decode('utf-8')
        return version_strings
    except:
        pass


def get_digital_signature(pe):
    if not pe.has_signatures:
        return None
    is_signed = False
    signers = list()
    for sign in pe.signatures:
        for s in sign.signers:
            is_signed = True
            signers.append(s.cert)
    if is_signed:
        print(f'{console.highlight("signature", bgColor=bgColor.YELLOW, textColor=textColor.BLACK)}')
        for cert in signers:
            print('\tsubject: ' + cert.subject)
        print(f'\tstatus: ', pe.verify_signature())
        print()

def get_subject_cn_signature(file):
    try:
        fil = pe.load_pe(file)
        if not fil.has_signatures:
            return None
        signers = list()
        for sign in fil.signatures:
            for s in sign.signers:
                signers.append(s.cert)
        return signers[len(signers) - 1].subject.split('CN=')[1].split(',')[0]
    except:
        pass

def get_packer(filename):
    pe = pefile.PE(filename)
    if not os.path.isfile(os.path.dirname(os.path.dirname(os.path.abspath(__file__))).replace('\\', '/') + '/../utils/peid/peid_signatures.txt'):
        print('Signatures file not found')
        return
    signatures = peutils.SignatureDatabase(os.path.dirname(os.path.dirname(os.path.abspath(__file__))).replace('\\', '/') + '/../utils/peid/peid_signatures.txt')
    match = signatures.match(pe)
    if match:
        return match[0]

def get_hashes(filename):
    hashes = dict()
    hashes['md5'] = md5(filename)
    hashes['sha256'] = sha256(filename)
    if is_pe(filename):
        hashes['imphash'] = imphash(filename)
        hashes['dhash'] = dhash(filename)
    if 'linux' in platform.system().lower():
        hashes['ssdeep'] = ssdeep(filename)
        hashes['tlsh'] = tlsh(filename)
    return hashes

def md5(filename):
    BSIZE = 65536
    hashmd5 = hashlib.md5()
    f = open(filename, 'rb')
    while True:
        binary_content =  f.read(BSIZE)
        if not binary_content:
            break
        hashmd5.update(binary_content)
    return hashmd5.hexdigest()

def sha256(filename):
    BSIZE = 65536
    hash256 = hashlib.sha256()
    f = open(filename, 'rb')
    while True:
        binary_content = f.read(BSIZE)
        if not binary_content:
            break
        hash256.update(binary_content)
    return hash256.hexdigest()

def imphash(filename):
    pe = pefile.PE(filename)
    return pe.get_imphash()

# ref: https://gist.github.com/fr0gger/1263395ebdaf53e67f42c201635f256c
def dhash(filename):
    from PIL import Image
    import warnings
    warnings.simplefilter("ignore")
    pe = load_pe(filename)
    if not pe.has_resources or not pe.resources_manager.has_icons or not pe.resources_manager.icons:
        return
    hash_size = 8
    pe.resources_manager.icons[0].save('ico')
    image = Image.open('ico')
    image = image.convert('L').resize((hash_size + 1, hash_size), Image.ANTIALIAS)
    difference = []
    for row in range(hash_size):
        for col in range(hash_size):
            pixel_left = image.getpixel((col, row))
            pixel_right = image.getpixel((col + 1, row))
            difference.append(pixel_left > pixel_right)
    decimal_value = 0
    hex_string = []
    for index, value in enumerate(difference):
        if value:
            decimal_value += 2**(index % 8)
        if (index % 8) == 7:
            hex_string.append(hex(decimal_value)[2:].rjust(2, '0'))
            decimal_value = 0
    os.remove("ico")
    return ''.join(hex_string)

def ssdeep(filename):
    import pydeep
    return pydeep.hash_file(filename).decode()

def tlsh(filename):
    import tlsh
    return tlsh.hash(open(filename, 'rb').read())

def is_packed(entropy):
    if entropy > 7.2:
        return "yes"
    elif entropy > 6.7:
        return "maybe"
    else:
        return "-"

def get_section_flags(section):
    flags = ''
    if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_READ):
        flags += 'r'
    if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE):
        flags += 'w'
    if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE):
        flags += 'x'
    return flags

def get_entropy(data):
    if not data:
        return None
    import collections
    from scipy.stats import entropy
    bases = collections.Counter([tmp_base for tmp_base in data])
    dist = [x/sum(bases.values()) for x in bases.values()]
    return entropy(dist, base=2)

def get_sections(pe):
    print('sections')
    headers = ['name', 'raw_size', 'virtual_size', 'flags', 'entropy', 'packed?', 'ep']
    ep = pe.optional_header.addressof_entrypoint
    data = list()
    for section in pe.sections:
        row = list()
        row.append(section.name)
        row.append(f'{colors.ATTENTION}' + str(section.sizeof_raw_data) + f'{colors.RESET}' if section.sizeof_raw_data == 0 else str(section.sizeof_raw_data))
        row.append(str(section.virtual_size))
        row.append(f'{colors.ATTENTION}' + str(get_section_flags(section)) + f'{colors.RESET}' if get_section_flags(section) == 'rwx' else str(get_section_flags(section)))
        if section.content:
            entropy = get_entropy(section.content)
            ispacked = is_packed(entropy)
        else:
            entropy = '-'
            ispacked = '-'
        row.append(str(entropy))
        row.append(f'{colors.ATTENTION}' + ispacked + f'{colors.RESET}' if not "-" in ispacked else ispacked)
        if ep >= section.virtual_address and ep <  section.virtual_address + section.virtual_size:
            row.append('here')
        data.append(row)
    if pe.overlay:
        entropy = get_entropy(pe.overlay)
        row = list()
        row.append('overlay')
        row.append('')
        row.append('')
        row.append('')
        row.append(str(entropy))
        ispacked = is_packed(entropy)
        row.append(f'{colors.ATTENTION}' + ispacked + f'{colors.RESET}' if not "-" in ispacked else ispacked)
        row.append('')
        data.append(row)
    print(tabulate(data, headers = headers, tablefmt = 'psql'))
    print()
       
def get_imports(pe):
    if not pe.has_imports:
        return None
    import_list = list()
    imported_library = dict()
    imported_functions = list()
    just_libraries = list()
    for imp in pe.imports:
        just_libraries.append(imp.name)
        imported_library['library_name'] = imp.name
        for func in imp.entries:
            imported_functions.append(func.name)
        imported_library['imported_functions'] = imported_functions
        import_list.append(imported_library)
    if just_libraries:
        print('imports: ', end='')
        print(*just_libraries, sep=', ')
        print()
        malapi.print_malapi_matches(import_list)

def get_exports(pe):
    if not pe.has_exports:
        return None
    exports = list()
    i = 0
    for exp in pe.exported_functions:
        exports.append(exp.name)
        i += 1
        if i == 5:
            exports.append('and more.')
            break
    if exports:
        print('exports: ', end='')
        print(*exports, sep = ', ')
        print()

def disassemble_ep(filename):
    pe = pefile.PE(filename)
    ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep = ep_rva + pe.OPTIONAL_HEADER.ImageBase
    data = pe.get_memory_mapped_image()[ep_rva:ep_rva+100]
    CODE_BITNESS = 32
    if 'x86-64' in magic.from_file(filename):
        CODE_BITNESS = 64
    decoder = Decoder(CODE_BITNESS, data)
    formatter = Formatter(FormatterSyntax.MASM)
    print('EP disassembly ' + str(CODE_BITNESS) + ' bits\n')
    for instr in decoder:
        start_index = instr.ip
        bytes_str = data[start_index:start_index + instr.len].hex().upper()
        disasm = formatter.format(instr)
        print(f"{instr.ip:05X} {bytes_str:20} {disasm}")
    print()

def disassemble_sc(filename):
    first_bytes = 100
    file = open(filename, "rb")
    data = file.read()
    data = data[:first_bytes]
    file.close()
    CODE_BITNESS = 32
    decoder = Decoder(CODE_BITNESS, data)
    formatter = Formatter(FormatterSyntax.MASM)
    print(str(first_bytes) + ' first bytes of x86 shellcode\n')
    for instr in decoder:
        start_index = instr.ip
        bytes_str = data[start_index:start_index + instr.len].hex().upper()
        disasm = formatter.format(instr)
        print(f"{instr.ip:05X} {bytes_str:20} {disasm}")
    print()

def disassemble_sc64(filename):
    first_bytes = 100
    file = open(filename, "rb")
    data = file.read()
    data = data[:first_bytes]
    file.close()
    CODE_BITNESS = 64
    decoder = Decoder(CODE_BITNESS, data)
    formatter = Formatter(FormatterSyntax.MASM)
    print(str(first_bytes) + ' first bytes of x64 shellcode\n')
    for instr in decoder:
        start_index = instr.ip
        bytes_str = data[start_index:start_index + instr.len].hex().upper()
        disasm = formatter.format(instr)
        print(f"{instr.ip:05X} {bytes_str:20} {disasm}")
    print()

def get_capa(filename):
    if not os.path.isfile(filename) or not pe.is_pe(filename):
        return None
    print(f'{console.highlight("capa", bgColor=bgColor.BLUE, textColor=textColor.WHITE)}', end=' ')
    capa_json = run_capa(filename)
    mitre = set()
    if capa_json:
        for r in capa_json.get('rules'):
            rule = capa_json.get('rules').get(r)
            if rule.get('meta'):
               for technique in rule.get('meta').get('att&ck'):
                   mitre.add(technique.get('id'))
    return list(mitre)

def get_printable_size(byte_size):
    BASE_SIZE = 1024.00
    MEASURE = ["B", "KB", "MB", "GB", "TB", "PB"]
    def _fix_size(size, size_index):
        if not size:
            return "0"
        elif size_index == 0:
            return str(size)
        else:
            return "{:.2f}".format(size)
    current_size = byte_size
    size_index = 0
    while current_size >= BASE_SIZE and len(MEASURE) != size_index:
        current_size = current_size / BASE_SIZE
        size_index = size_index + 1
    size = _fix_size(current_size, size_index)
    measure = MEASURE[size_index]
    return size + ' ' + measure

def get_printable_name(filename, md5, sha256):
    if not filename:
        return '<none>'
    return filename.replace(sha256, '<sha256>').replace(md5, '<md5>')[-50:]