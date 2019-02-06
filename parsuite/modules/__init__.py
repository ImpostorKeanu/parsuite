from . import NmapXMLServiceParser
from . import NmapXMLSMBSecurityMode
from . import NessusHostDumper 
from . import URLCrazyToCSV
from . import ReconNGContactDumper
from sys import modules

handles = {
            modn.split('.')[-1]:mod for modn,mod in modules.items()
            if modn.startswith('parsuite.modules') and modn != 'parsuite.modules'
          }
