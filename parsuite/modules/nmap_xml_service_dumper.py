from parsuite.core.argument import Argument,DefaultArguments
from parsuite.abstractions.xml.generic import network_host as NH
from parsuite import helpers
from parsuite.core.suffix_printer import *
#import xml.etree.ElementTree as ET
from lxml import etree as ET
import argparse
import os

help='Accept a XML file generated '\
     'by Nmap and write the output to a local directory structure, '\
     'organized by service, for easy browsing.'

args = [
    DefaultArguments.input_file,
    Argument('--tcpwrapped', '-tw', action='store_true',
        help='Enable dumping of tcpwrapped services.'),
    Argument('--output-directory', '-od', required=True,
        help='Output directory.')
]

def parse(input_file=None, output_directory=None,
        tcpwrapped=None, **kwargs):

    bo = base_output_path = helpers.handle_output_directory(
        output_directory
    )

    # parse the input file
    tree = ET.parse(input_file)

    os.chdir(output_directory)
    services = set(tree.xpath('//service/@name'))
    sprint(f'Parsing {len(services)} services...\n')

    hcache = []
    for sname in services:

        # skip tcpwrapped services unless specified
        if sname == 'tcpwrapped' and not tcpwrapped:
            continue

        hosts = tree.findall(
            f'.//service[@name="{sname}"]/../../../status[@state="up"]/..'
        )
        
        if hosts:
            os.mkdir(sname)
            os.chdir(sname)
        else:
            continue

        print(f'- {sname}')

        '''
        {
            protocol:{
                'addresses':[],
                'sockets':[],
                'fqdns':[],
                'fsockets':[],
            }
        }
        '''
        to_dump = {}

        # Iterate over a set of unique protocol/port combinations
        # associated with a given service. Each item of the set will
        # be a tuple in the following form: (protocol,port)
        for tup in set([
                (p.get('protocol'),p.get('portid'),) for p in
                tree.xpath(f'//service[@name="{sname}"]/..')
            ]):

            protocol, port = tup

            if protocol not in to_dump:

                to_dump[protocol] = {
                    'addresses':[],
                    'sockets':[],
                    'fqdns':[],
                    'fsockets':[]
                }

            dct = to_dump[protocol]

            # 
            for ehost in tree.xpath(
                    f'.//service[@name="{sname}"]/../../../status[@state=' \
                    f'"up"]/../ports/port[@protocol="{protocol}" and ' \
                    f'@portid="{port}"]/../..'
                ):

                try:
                    host = hcache[hcache.index(ehost.get('addr'))]
                except:
                    host = NH.FromXML.host(ehost)

                if host.ipv4_address:
                    dct['addresses'].append(host.ipv4_address)
                    dct['sockets'].append(
                        host.ipv4_address+f':{port}'
                    )

                if host.ipv6_address:
                    dct['addresses'].append(host.ipv6_address)
                    dct['sockets'].append(
                        f'[{host.ipv6_address}]:{port}'
                    )

                dct['fqdns'] += host.hostnames

                for hn in host.hostnames:
                    dct['fsockets'].append(hn+f':{port}')

        # =======================================
        # DUMP OUTPUT TO DISK FOR CURRENT SERVICE
        # =======================================

        for proto,output in to_dump.items():

            for tpe,lst in output.items():

                if not lst: continue

                with open(f'{protocol}_{tpe}.txt','w') as outfile:

                    outfile.write(
                        '\n'.join(sorted(list(set(lst))))
                    )

        # Change back to main output directory
        os.chdir('..')

    return 0
