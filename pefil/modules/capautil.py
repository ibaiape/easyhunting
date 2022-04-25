import json

def run_capa(filename):
    try:
        from utils.capa.capa import main as capa
        capa_report = capa.main(filename)
        if capa_report:
            return json.loads(capa_report)
    except Exception as e:
        print(e)
        pass
