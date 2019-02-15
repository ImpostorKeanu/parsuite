#from . import NmapXMLServiceParser
#from . import NmapXMLSMBSecurityMode
#from . import NessusHostDumper 
#from . import URLCrazyToCSV
#from . import ReconNGContactDumper
#from . import NmapTopPortDumper
from sys import modules
from pathlib import Path
from importlib import import_module

for f in Path('.').glob('**/*.py'):
    if p.name.startswith('_'): continue
    import_module('.'+p.name, 'parsuite')

handles = {
            modn.split('.')[-1]:mod for modn,mod in modules.items()
            if modn.startswith('parsuite.modules') and modn != 'parsuite.modules'
          }
