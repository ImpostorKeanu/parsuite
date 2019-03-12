from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
import xml.etree.ElementTree as ET
import argparse
import os
from re import search

help='Stuff'\

args = [
    DefaultArguments.input_file,
]

def parse(input_file=None, **kwargs):


    # parse the input file
    tree = ET.parse(input_file)

    for host in tree.findall('.//host'):

        # EXTRACT THE STATUS
        status = host.find('status').attrib['state']
        if status != 'up': continue

        # EXTRACT ADDRESS
        # address = host.find('address').attrib['addr']

        # EXTRACT ALL KNOWN HOSTNAMES
        hostnames = [
            hostname.attrib['name'] for hostname in host.findall('.//hostname')
        ]
        hostnames.append(host.find('address').attrib['addr'])

        # BEGIN ENUMERATING PORTS
        for port in host.findall('.//port'):
            
            # ASSURE THE PORT IS OPEN
            if port.find('.//state').attrib['state'] != 'open':
                continue

            portid = port.attrib['portid']
            service = port.find('.//service')
            sname = service.attrib['name']

            # ASSURE THIS IS AN HTTP SERVICE
            if not search('http',sname): continue

            # DETERMINE IF THERE IS A TUNNEL
            tunnel = None
            if 'tunnel' in service.attrib: tunnel = service.attrib['tunnel']

            for hostname in hostnames:

                if not search('https',sname):

                    if tunnel == 'ssl':
                        print(f'https://{hostname}:{portid}')
                    else:
                        print(f'http://{hostname}:{portid}')

                else:

                    print(f'https://{hostname}:{portid}')

    return 0
