import json
from collections import defaultdict
import os

def get_color_by_intel(intel):
    if intel == 'capa':
        return '#f5e380'
    if intel == 'virustotal':
        return '#9dcdff'
    if intel == 'alienvault':
        return '#b7e083'
    if intel == 'triage':
        return '#e96767'

def get_techniques(mitre):
    intels = ['capa', 'virustotal', 'alienvault', 'triage'] # sorted by less confidence (for me)
    techniques = defaultdict(dict)
    for intel in intels:
        if not mitre.get(intel):
            continue
        for technique in mitre.get(intel):
            one = dict()
            if techniques.get(technique):
                one = techniques.get(technique)
                one['color'] = get_color_by_intel(intel)
                one['comment'] = one['comment'] + intel + '\n'
            else:
                one['techniqueID'] = technique
                one['color'] = get_color_by_intel(intel)
                one['comment'] = intel + '\n'
            techniques[technique] = one
    return list(techniques.values())

def create_matrix(id, mitre):
    with open(os.path.dirname(os.path.abspath(__file__)).replace('\\', '/') + '/template-layer.json') as f:
        layer = json.load(f)
    layer['name'] = id
    techniques = get_techniques(mitre)
    if not techniques:
        return
    layer['techniques'] = techniques
    dirpath = "mitre_navigator_reports"
    if not os.path.exists(dirpath):
        os.mkdir(dirpath)
    with open(dirpath + '/' + id + ".navigator", "w") as f:
        f.write(json.dumps(layer, indent=4))
        print(id + ".navigator has been generated in " + dirpath + '!\n')
        print("you can create the 'enterprise' mitre attack matrix by loading it here: " + "https://mitre-attack.github.io/attack-navigator/")