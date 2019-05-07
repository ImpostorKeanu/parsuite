from parsuite.core.argument import Argument
from parsuite import helpers
from parsuite.core.suffix_printer import *
from pathlib import Path
from sys import exit,stderr,stdout
from collections import namedtuple
import re

help='Parse the Nmap services file and dump the most commonly open ports.'

default_services_path = '/usr/share/nmap/nmap-services'

args = [
    Argument('--input-file','-if', default=default_services_path,
        help='Input file to parse'),
    Argument('--top','-t', default=10, type=int,
        help='The top number of ports to return'),
    Argument('--csv-only','-csv', action='store_true',
        help='Return only the CSV output'),
    Argument('--all-protocols','-ap', action='store_true',
        help='Determine if all protocols should be dumped'),
    Argument('--tcp', action='store_true',
        help='Dump the top tcp services'),
    Argument('--sctp', action='store_true',
        help='Dump the top sctp services'),
    Argument('--udp',action='store_true',
        help='Dump the top udp services'),
    Argument('--name-search',  default=[],
        nargs='+',
        help='Search all service names and dump matches'),
    Argument('--minimum-frequency', '-mf', default=0.000001,
        type=float,
        help='Minimum frequency that must be met for a given service'),
    Argument('--offset',default=0,
        type=int,
        help='Dump top ports from offset onward.')
]

Service = namedtuple(
    'Service',
    ['name','port','protocol','frequency']
)

service_re = re.compile('^(?P<name>(\w|\-|\.|:)+)\s+'\
    '(?P<port>[0-9]{1,5})/'\
    '(?P<protocol>(tcp|udp|sctp))\s+'\
    '(?P<frequency>[0-9]\.[0-9]+)')

def parse_service(line,minimum_frequency=None):

    # strip whitespace
    line = line.strip()

    # assure content is there for parsing
    if not line or line[0] == '#': return None

    # create the namedtuple
    groups = re.match(service_re, line).groupdict()
    groups['frequency'] = float(groups['frequency'])
    if minimum_frequency and groups['frequency'] < minimum_frequency:
        return None
    groups['port'] = int(groups['port'])

    return Service(**groups)

def parse(csv_only=None,
        tcp=None, udp=None, sctp=None, top=None, all_protocols=False,
        minimum_frequency=None, name_search=[], offset=0,**kwargs):

    if offset >= top:
        raise Exception('Offset must be less than top')

    if not Path(default_services_path).exists() and not input_file:
        esprint('Services file not detected. Either nmap isn\'t installed or you\'re not using'\
            ' a real computer (Winders)\n\n Exiting like a pretentious boss')
        exit()


    # make a list of desired protocols
    protocols = []

    if udp: protocols.append('udp')
    if tcp: protocols.append('tcp')
    if sctp: protocols.append('sctp')
    if not protocols or all_protocols: protocols = ['tcp','udp']

  
    services = {}

    if name_search:
        
        for proto in protocols: services[proto] = []

        for search_val in name_search:
    
            with open(default_services_path) as service_file:
    
                for line in service_file:
    
                    service = parse_service(line)
                    if not service or not service.protocol in protocols: continue
    
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

    else:

        esprint(f'Dumping the {top} ports')
        for proto in protocols: services[proto] = {
            'services':{},
            'frequencies':[],
            'top_ports':[]
        }

        # parse the services
        with open(default_services_path) as service_file:
    
            for line in service_file:
                
                service = parse_service(line)
    
                if not service or not service.protocol in protocols:
                    continue
    
                srvs = services[service.protocol]['services']
                freqs = services[service.protocol]['frequencies']
    
                if service.frequency not in freqs:
                    freqs.append(service.frequency)
    
                if not service.frequency in srvs:
                    srvs[service.frequency] = [service]
                else:
                    srvs[service.frequency].append(service)
    
        # Collecting the top ports per protocol
        for proto in protocols:
    
            srvs = services[proto]

            if offset:
                freqs = reversed(sorted(srvs['frequencies'],key=float)[-top:][:-offset])
            else:
                freqs = reversed(sorted(srvs['frequencies'],key=float)[-top:])

            if not csv_only:
                print('{:-<39}'.format(''),file=stderr)
                print('{: >24}'.format(proto.upper()+' Services'),file=stderr)
                print('{:-<39}'.format(''),file=stderr)
                print('{:16}{:15} Service'.format('Freq','Port/Proto'),file=stderr)
                print('{: <16}{: <15}{: >8}'.format('----','----------','-------'),file=stderr)
            for freq in freqs:
                for s in services[proto]['services'][freq]:
                    srvs['top_ports'].append(s.port)
                    if not csv_only:
                        print(f'{s.frequency:0<8}\t{str(s.port)+"/"+s.protocol:8}\t{s.name}',file=stderr)
            if not csv_only:
                print(file=stderr)
    
        if not csv_only:
            esprint('CSV List(s):\n')
        for protocol in protocols:
            esprint(f'{protocol}:')
            ports = ','.join(
                [str(p) for p in sorted(services[protocol]["top_ports"])]
            )
            print(ports)
    
    return 0
