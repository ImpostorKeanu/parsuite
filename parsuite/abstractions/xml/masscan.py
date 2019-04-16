from parsuite.abstractions.xml.generic.network_host import *
from parsuite.core.suffix_printer import *
from sys import exit

class MasscanHost(Host):
    
    def to_uris(self,*args,**kwargs):
        esprint(
            'Error: Masscan does not fingerprint services and ' \
            'cannot produce URIs'
        )
        exit()
