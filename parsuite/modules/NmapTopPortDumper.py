from parsuite.core.argument import Argument
from parsuite import helpers
from parsuite.core.suffix_printer import *
from pathlib import Path
from sys import exit
from collections import namedtuple
from re import compile,match

help='Parse the Nmap services file and dump the most commonly open ports.'

default_services_path = '/usr/share/nmap/nmap-services'

args = [
    Argument('--input-file','-if', default=default_services_path,
        help='Input file to parse'),
    Argument('--top','-t', required=True, type=int,
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
        help='Dump the top udp services')
]

Service = namedtuple(
    'Service',
    ['name','port','protocol','frequency']
)

service_re = compile('^(?P<name>(\w|\-|\.|:)+)\s+'\
    '(?P<port>[0-9]{1,5})/'\
    '(?P<protocol>(tcp|udp|sctp))\s+'\
    '(?P<frequency>[0-9]\.[0-9]+)')

def parse(csv_only=None,
        tcp=None, udp=None, sctp=None, top=None, all_protocols=False, **kwargs):

    if not Path(default_services_path).exists() and not input_file:
        sprint('Services file not detected. Either nmap isn\'t installed or you\'re not using'\
            ' a real computer (Winders)\n\n Exiting like a pretentious boss')
        exit()

    sprint(f'Dumping the {top} ports\n')

    # make a list of desired protocols
    protocols = []

    if udp:
        protocols.append('udp')

    if tcp:
        protocols.append('tcp')

    if sctp:
        protocols.append('sctp')

    if not protocols or all_protocols:
        protocols = ['tcp','udp','sctp']

    services = {}
    for proto in protocols:
        services[proto] = {'services':{},'frequencies':[],'top_ports':[]}
    
    # parse the services
    with open(default_services_path) as service_file:

        for line in service_file:

            # strip whitespace
            line = line.strip()

            # assure content is there for parsing
            if not line or line[0] == '#':
                continue

            # create the namedtuple
            groups = match(service_re, line).groupdict()
            groups['frequency'] = float(groups['frequency'])
            groups['port'] = int(groups['port'])
            service = Service(**groups)

            if not service.protocol in protocols:
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
        freqs = sorted(srvs['frequencies'],key=float)[-top:]
        if not csv_only:
            print('{:-<39}'.format(''))
            print('{: >24}'.format(proto.upper()+' Services'))
            print('{:-<39}'.format(''))
            print('{:16}{:15} Service'.format('Freq','Port/Proto'))
            print('{: <16}{: <15}{: >8}'.format('----','----------','-------'))
        for freq in freqs:
            for s in services[proto]['services'][freq]:
                srvs['top_ports'].append(s.port)

                if not csv_only:
                    print(f'{s.frequency:0<8}\t{str(s.port)+"/"+s.protocol:8}\t{s.name}')

        print()

    if not csv_only:
        print('CSV List(s):\n')
    for protocol in protocols:
        ports = ','.join(
            [str(p) for p in sorted(services[protocol]["top_ports"])]
        )
        print(f'{protocol}-csv: {ports}')

    return 0
