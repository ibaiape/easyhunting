#!/usr/bin/env python3
import argparse

from pefil import file
from intelligence import intel

if __name__ == "__main__":
	print('easy hunting tool - @ppt0\n')
	parser = argparse.ArgumentParser(prog=None, description="easy hunting tool", usage= "python easyhunting.py -f <filepath> -ep <filepath> -sc <sc32path> -sc64 <sc64path> -r <filepath> -m <filepath, hash> -i <filepath, hash, url, domain or ip> -b <iocs file> file -s <filepath> -q <vtiquery> -t <tag> -d <hash>")
	parser.add_argument('-f', '--file', dest='file', help='simple file report')
	parser.add_argument('-ep', '--entrypoint', dest='entrypoint', help='disassemble the file entrypoint')
	parser.add_argument('-sc', '--shellcode', dest='shellcode', help='disassemble a x86 shellcode')
	parser.add_argument('-sc64', '--shellcode64', dest='shellcode64', help='disassemble a x64 shellcode')
	parser.add_argument('-r', '--rules', dest='rules', help='get yara, sigma and ids rules from a file')
	parser.add_argument('-m', '--mitre', dest='mitre', help='get mitre attack about a file from intel sources')
	parser.add_argument('-i', '--intel', dest='intel', help='get threat info from intel sources')
	#parser.add_argument('-b', '--bulk', dest='bulk', help='get threat info from intel sources in a bulk process (file with a ioc in each row)')
	parser.add_argument('-s', '--similar', dest='similar', help='get similar files from intel sources')
	parser.add_argument('-q', '--query', dest='query', help='vt intelligence queries (pro api key is required)')
	parser.add_argument('-t', '--tag', dest='tag', help='get tag-based samples')
	parser.add_argument('-d', '--download', dest='download', help='download file from the wild')
	args = parser.parse_args()

	if args.file:
		file.simple_report(args.file)
	elif args.entrypoint:
		file.dis_ep(args.entrypoint)
	elif args.shellcode:
		file.dis_sc(args.shellcode)
	elif args.shellcode64:
		file.dis_sc64(args.shellcode64)
	elif args.rules:
		file.get_rules(args.rules)
	elif args.mitre:
		intel.get_mitre(args.mitre)
	elif args.intel:
		intel.get_intel(args.intel)
	elif args.similar:
		intel.get_similar(args.similar)
	elif args.query:
		intel.vtintelligence_query(args.query)
	elif args.tag:
		intel.get_files_from_tag(args.tag)
	elif args.download:
		intel.download_file(args.download)
	else:
		parser.print_help()
		exit()
	print('\nhave an easy threat hunting!')
	exit()