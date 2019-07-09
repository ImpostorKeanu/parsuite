from parsuite.core.argument import Argument
from parsuite.abstractions import misc
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
    Argument('--ranges-only','-r', action='store_true',
        help='Return only output as ranges'),
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


def parse(csv_only=None,
        tcp=None, udp=None, sctp=None, top=None, protocols=[], 
        name_search=[], offset=0, ranges_only=False, **kwargs):

    # ================
    # HANDLE ARGUMENTS
    # ================
    
    if not Path(default_services_path).exists() and not input_file:
        esprint('Services file not detected. Either nmap isn\'t installed or you\'re not using'\
            ' a real computer (Winders)\n\n Exiting like a pretentious boss')
        exit()

    if offset >= top: raise Exception('Offset must be less than top')

    # =======================
    # PARSE THE SERVICES FILE
    # =======================

    services = misc.nmap.parse_top_ports(
        default_services_path,name_search,protocols
    )

    # ============================
    # SELECT AND DUMP THE SERVICES
    # ============================

    csv_cache = {}

    range_svs = {}

    for proto,srvs in services.items():

        srvs = sorted(services[proto],reverse=True)
        if offset: srvs = srvs[offset:offset+top]
        else: srvs = srvs[:top]

        isrvs = sorted([s.port for s in srvs])

        range_svs[proto] = []

        counter, start, stop = 1, 0, 1
        while stop < len(isrvs):

            p0, p1 = isrvs[start], isrvs[stop]
            if p0+counter != p1 or stop == len(isrvs)-1:

                if stop-start == 1:

                    range_svs[proto].append(str(p0))
                    start += 1

                    if stop == len(isrvs)-1:

                        range_svs[proto].append(str(p1))

                else:

                    slce = [p for p in isrvs[start:stop]]
                    range_svs[proto].append(
                            '-'.join([str(slce[0]),str(slce[-1])])
                    )

                start = stop
                counter = 1

            else: counter += 1


            stop += 1

        srvs = sorted(srvs,reverse=True)
        csv_cache[proto] = ','.join(
            [str(p.port) for p in srvs]
        )

        if not csv_only and not ranges_only:

            print('{:-<39}'.format(''),file=stderr)
            print('{: >24}'.format(proto.upper()+' Services'),file=stderr)
            print('{:-<39}'.format(''),file=stderr)
            print('{:16}{:15} Service'.format('Freq','Port/Proto'),file=stderr)
            print('{: <16}{: <15}{: >8}'.format('----','----------','-------'),file=stderr)
        
            for s in srvs:
                print(
                    f'{s.frequency:0<11}\t{str(s.port)+"/"+s.protocol:8}\t{s.name}',
                    file=stderr
                )

            print(file=stderr)


    if ranges_only:
        esprint('Printing Range List(s)')
        for proto,ranges in range_svs.items():
            esprint(f'{proto}',suf='-')
            print(','.join(ranges))
    else:
        esprint('Printing CSV List(s)')
        for proto,ports in csv_cache.items():
            esprint(f'{proto}',suf='-')
            print(ports)
    
    return 0
