# easyhunting

This tool tries to facilitate the day to day of a threat hunter or malware analyst.

<span style="color:red">Important! easyhunting **does not upload** any info or samples to internet.</span>

Features:
* Get ***a simple file report***. It includes peid signature, similarity-based hashes, sections overview, signature, [malapi](https://malapi.io/) matches and intelligence sources hits.
* The ***disassembly of the first bytes*** to identify in a fast way if pe file has a non-common ep like packer or file infector or if the hex chunk is a shellcode. If you want to disassemble a shellcode, you have to choose the architecture (sc to x86 and sc64 to x64)
* Get ***yara, sigma and ids rules*** of a sample from an arbitrary yara rule repository (e.g. [this repo](https://github.com/Yara-Rules/rules)) and intelligence sources.
* Get ***mitre attack techniques*** used by a sample. Techniques are obtained via triage, alienvault, virustotal and capa. Also, a json file is created in "mitre_navigator_reports" folder to import in mitre attack [navigator](https://mitre-attack.github.io/attack-navigator/) framework.
* Get ***potencial similar files*** using similarity-based hashes such as imphash, ssdeep, tlsh and icon dhash, and other features like signature, similar size and similar metadata. Note: ssdeep and tlsh hashes are not available in windows system.
* Get ***threat intel information about file, ip, domain and url*** from intel sources. It does not pretend to show a extended report,  but rather get the most the most important info (for me) with a tag model presenting the following structure:
    - *basic information* about the sample
    - *tags* extracted from intel sources
    - *have* highlights the interesting info (for me again) in a fast way
    - *ttps* shows mitre-based techniques used by the sample
    - *link* to full report
* ***Virustotal Intelligence Queries*** to improve the similar file search ([documentation](https://support.virustotal.com/hc/en-us/articles/360001385897-File-search-modifiers)). Note: pro api key is required!
* ***See the latest malware*** in the wild searching with tags.
* ***Download samples*** from intel sources. The samples are downloaded in "downloaded_samples" folder.

***Intel sources available!***: *virustotal, bazaar, urlhaus, threatfox, alienvault, triage* and *tweetfeed*. You just need api key for virustotal and triage.

***To-do***
* Get threat info from intel sources in a bulk process (file with a ioc in each row).

***Contributors***

[<img alt="ppt0" src="https://img.shields.io/badge/linkedin-ppt0-blue">](https://www.linkedin.com/in/jtmartinezgarre/)

If you want to participate and join the project, let me know!

***How to use?*** [here](#Usage)

### **Installation**
1. Install Python3 (and create a virtual environment)
            `python3.9 -m venv easyhunting_env`
            `source easyhunting_env/bin/activate`
2. Download project with: `git clone https://github.com/ppt0/easyhunting.git`
3. Install python packages
- for linux: `python -m pip install -r linux-requirements.txt`
- for windows: `python -m pip install -r windows-requirements.txt`
4. Run easyhunting.py

### **Config file**
```
[apis]
virustotal = <vt-api-key>
triage = <triage-api-key>

[limits]
similar = 15
tags = 10
vtintelligence = 15
```

Limits indicate the number of results in each request. For instance, with tags = 10, the tool will only show the last 10 malware in each intel source with that tag. 
Note: take care with high value in "similar", since it could take a long time.

#### **Capa 3.2.0 integration**
1. Download the latest release (version 3.2.0) from [capa](https://github.com/mandiant/capa/archive/refs/tags/v3.2.0.zip) repo.
2. Extract .zip file in "utils" folder and rename folder from "capa-3.2.0" to "capa".
3. Download capa rules (version 3.2.0) from [here](https://github.com/mandiant/capa-rules/releases/tag/v3.2.0), extract them in "capa" folder and rename folder from "capa-rules-3.2.0" to "rules".
4. Change the following code in "capa/capa/main.py":

line 849:
```
def main(argv=None):
```
--
```
def main(filename, argv=None):
    argv = ['--rules', os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '/rules', '-j', '-q', filename]
```

line 954:
```
        # file limitations that rely on non-file scope won't be detected here.
        # nor on FunctionName features, because pefile doesn't support this.
        if has_file_limitation(rules, pure_file_capabilities):
            # bail if capa encountered file limitation e.g. a packed binary
            # do show the output in verbose mode, though.
            if not (args.verbose or args.vverbose or args.json):
                logger.debug("file limitation short circuit, won't analyze fully.")
                return E_FILE_LIMITATION
```
--
```
    if has_file_limitation(rules, pure_file_capabilities):
        return None
```

line 1028:
```
    if args.json:
        print(capa.render.json.render(meta, rules, capabilities))
```
--
```
    if args.json:
        return capa.render.json.render(meta, rules, capabilities)
```

line 235:
```
def has_file_limitation(rules: RuleSet, capabilities: MatchResults, is_standalone=True) -> bool:
    file_limitation_rules = list(filter(is_file_limitation_rule, rules.rules.values()))

    for file_limitation_rule in file_limitation_rules:
        if file_limitation_rule.name not in capabilities:
            continue

        logger.warning("-" * 80)
        for line in file_limitation_rule.meta.get("description", "").split("\n"):
            logger.warning(" " + line)
        logger.warning(" Identified via rule: %s", file_limitation_rule.name)
        if is_standalone:
            logger.warning(" ")
   
         logger.warning(" Use -v or -vv if you really want to see the capabilities identified by capa.")
        logger.warning("-" * 80)

        # bail on first file limitation
        return True

    return False
```
--
```
def has_file_limitation(rules: RuleSet, capabilities: MatchResults, is_standalone=True) -> bool:
    file_limitation_rules = list(filter(is_file_limitation_rule, rules.rules.values()))

    for file_limitation_rule in file_limitation_rules:
        if file_limitation_rule.name not in capabilities:
            continue
        # bail on first file limitation
        return True
    return False
```

#### **Yara rules integration**
1. Create "yara_rules" folder in "utils".
2. `git clone https://github.com/Yara-Rules/rules` in "yara_rules" folder.
3. If linux, comment `malware/MALW_AZORULT.yar` in malware_index.yar (dependency error)

Note: if you want to use other yara rules repo, you just have to change the .yar file path in "pefil/modules/yarautil.py".

### **Usage**

demo malware hash: `c9de316342aff789e9dcd725b893f48256f381c936ba19a7ccd9336e1ed9cace`

-f <filepath>, --file <filepath> -> simple file report
![Alt text](demo/file1.PNG?raw=true "Title")
![Alt text](demo/file2.PNG?raw=true "Title")
  
-ep <filepath>, --entrypoint <filepath> -> ep disassembly
 ![Alt text](demo/ep.PNG?raw=true "Title")

-r <filepath>, --rules <filepath> -> get yara, sigma and ids rules from a file
 ![Alt text](demo/rules1.PNG?raw=true "Title")
 ![Alt text](demo/rules2.PNG?raw=true "Title")

-m <filepath, hash>, --mitre <filepath, hash> -> get mitre techniques about a file from intel sources
 ![Alt text](demo/mitre1.PNG?raw=true "Title")
 ![Alt text](demo/mitre2.PNG?raw=true "Title")
 ![Alt text](demo/mitre3.PNG?raw=true "Title")

-i <filepath, hash, url, domain or ip>, --intel <filepath, hash, url, domain or ip> -> get intel info about file, hash, url, domain and ip
 ![Alt text](demo/intel1.PNG?raw=true "Title")
 ![Alt text](demo/intel2.PNG?raw=true "Title")
 ![Alt text](demo/intel3.PNG?raw=true "Title")

-s <filepath>, --similar <filepath> -> get similar files from intel sources
 ![Alt text](demo/similar1.PNG?raw=true "Title")
 ![Alt text](demo/similar2.PNG?raw=true "Title")
 ![Alt text](demo/similar3.PNG?raw=true "Title")

-q <vtiquery>, --query <vtiquery> -> VT Intelligence Queries
 ![Alt text](demo/vti.PNG?raw=true "Title")

-t <tag>, --tag <tag> -> get tag-based samples
 ![Alt text](demo/tag1.PNG?raw=true "Title")
 ![Alt text](demo/tag2.PNG?raw=true "Title")
 ![Alt text](demo/tag3.PNG?raw=true "Title")

-d <hash>, --download <hash> -> download file from the wild
 ![Alt text](demo/download.PNG?raw=true "Title")
