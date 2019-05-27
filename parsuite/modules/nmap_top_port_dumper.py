from parsuite.core.argument import Argument
from parsuite import helpers
from parsuite.core.suffix_printer import *
from pathlib import Path
from sys import exit,stderr,stdout
from collections import namedtuple
import re

from sys import exit

help='Parse the Nmap services file and dump the most commonly open ports.'

default_services_path = '/usr/share/nmap/nmap-services'

args = [
    Argument('--input-file','-if', default=default_services_path,
        help='Input file to parse'),
    Argument('--top','-t', default=10, type=int,
        help='The top number of ports to return'),
    Argument('--csv-only','-csv', action='store_true',
        help='Return only the CSV output'),
    Argument('--protocols','-p',
        choices=['tcp','udp','sctp'],
        default=['tcp'],
        nargs='+',
        help='Protocols to dump. Default: tcp'),
    Argument('--name-search',  default=[],
        nargs='+',
        help='Search all service names and dump matches'),
    Argument('--offset',default=0,
        type=int,
        help='Dump top ports from offset onward.')
]


service_re = re.compile('^(?P<name>(\w|\-|\.|:)+)\s+'\
    '(?P<port>[0-9]{1,5})/'\
    '(?P<protocol>(tcp|udp|sctp))\s+'\
    '(?P<frequency>[0-9]\.[0-9]+)')

class Service:

    def __init__(self,name,port,protocol,frequency):

        if not type(frequency) == float:
            raise TypeError('Frequency must be a float')

        self.name = name
        self.port = port
        self.protocol = protocol
        self.frequency = frequency

    def __repr__(self):

        return f'< [Service] name: {self.name} port: {self.port} '\
            f'protocol: {self.protocol} frequency: {self.frequency} >'

    def __lt__(self, val):

        classes = [Service,float]

        if not val.__class__ in classes:
            raise TypeError(
                'Service comparison must occur between a float or service'
            )

        if val.__class__ == Service: val = val.frequency

        if self.frequency < val:
            return True
        else:
            return False

    @staticmethod
    def from_line(line):
        '''Create a Service object from a line in the Nmap
        services file.
        '''
        line = line.strip()
    
        # create the namedtuple
        groups = re.match(service_re, line).groupdict()
        groups['frequency'] = float(groups['frequency'])
        groups['port'] = int(groups['port'])
    
        return Service(**groups)

def parse(csv_only=None,
        tcp=None, udp=None, sctp=None, top=None, protocols=[], 
        name_search=[], offset=0,**kwargs):

    #if offset >= top:
    #    raise Exception('Offset must be less than top')

    if not Path(default_services_path).exists() and not input_file:
        esprint('Services file not detected. Either nmap isn\'t installed or you\'re not using'\
            ' a real computer (Winders)\n\n Exiting like a pretentious boss')
        exit()

    # =============================
    # SEARCH SERVICE NAMES AND DUMP
    # =============================
    
    services = {}

    if name_search:
        
        for proto in protocols: services[proto] = []

        for search_val in name_search:
    
            with open(default_services_path) as service_file:
    
                for line in service_file:
    
                    if not line or line[0] == '#': continue

                    service = Service.from_line(line)
                    if not service.protocol in protocols: continue
    
                    if re.search(re.escape(search_val),service.name):
                        services[service.protocol].append(service)
    
        for proto in protocols:

            srvs = services[proto]
            if not csv_only:

                print('{:-<39}'.format(''),file=stderr)
                print('{: >24}'.format(proto.upper()+' Services'),file=stderr)
                print('{:-<39}'.format(''),file=stderr)
                print('{:16}{:15} Service'.format('Freq','Port/Proto'),file=stderr)
                print('{: <16}{: <15}{: >8}'.format('----','----------','-------'),file=stderr)
            
                for s in services[proto]:
                    print(
                        f'{s.frequency:0<8}\t{str(s.port)+"/"+s.protocol:8}\t{s.name}',
                        file=stderr
                    )

            if not csv_only:
                print(file=stderr)
    
        if not csv_only:
            esprint('CSV List(s):\n')
        for protocol in protocols:
            esprint(f'{protocol}:')
            ports = ','.join(
                [str(p.port) for p in sorted(services[protocol])]
            )
            print(ports)

    # =======================
    # DUMP BASED ON FREQUENCY
    # =======================

    else:

        esprint(f'Dumping the {top} ports')
        for proto in protocols: services[proto] = []

        # parse the services
        with open(default_services_path) as service_file:
    
            for line in service_file:
                
                if not line or line[0] == '#': continue
                service = Service.from_line(line)
    
                if not service.protocol in protocols:
                    continue

                services[service.protocol].append(service)

        # Collecting the top ports per protocol
        for proto in protocols:
    
            srvs = sorted(services[proto],reverse=True)

            if offset:
                srvs = srvs[offset:offset+top]
            else:
                srvs = srvs[:top]
            
            services[proto] = srvs
            
            if not csv_only:
                print('{:-<39}'.format(''),file=stderr)
                print('{: >24}'.format(proto.upper()+' Services'),file=stderr)
                print('{:-<39}'.format(''),file=stderr)
                print('{:16}{:15} Service'.format('Freq','Port/Proto'),file=stderr)
                print('{: <16}{: <15}{: >8}'.format('----','----------','-------'),file=stderr)

                for s in srvs:
                    print(f'{s.frequency:0<8}\t{str(s.port)+"/"+s.protocol:8}\t{s.name}',file=stderr)

                print(file=stderr)
    
        if not csv_only: esprint('CSV List(s):\n')

        for protocol in protocols:
            esprint(f'{protocol}:')
            ports = ','.join(
                [str(p.port) for p in services[protocol]]
            )
            print(ports)
    
    return 0
