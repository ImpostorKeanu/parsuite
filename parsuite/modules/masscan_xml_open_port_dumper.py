from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
import xml.etree.ElementTree as ET
import argparse
import os

help='Dump hosts and open ports from a masscan xml file.'

formats={
    'default':'{protocol}/{port}',
    'socket':'{protocol}://{address}:{port}'
}

args = [
    DefaultArguments.input_file,
    Argument('--fmt','-f',choices=list(formats.keys()),
        default='default')
]

def protocol_printer(protocols,address=None,fmt='{protocol}/{port}',require_open=True):

    for protocol,states in protocols.items():

        for state,ports in states.items():

            if require_open and state != 'open':
                continue
    
            for port in ports:
    
                print(
                    fmt.format(address=address,
                        protocol=protocol,
                        port=port)
                )

def parse(input_file=None, fmt=None, **kwargs):

    report = {}

    # parse the input file
    tree = ET.parse(input_file)
    for host in tree.findall(
        './/host/ports/port/state[@state="open"]../../..'):
        
        address = host.find('address').get('addr')
        ports = {}

        for port in host.findall('.//port/state[@state="open"]..'):

            protocol = port.get('protocol')
            portid = port.get('portid')
            state = port.find('state').get('state')

            if protocol not in ports:
                ports[protocol] = {state:[int(portid)]}

        report[address] = ports

    for address,protocols in report.items():
        
        header = f'Open ports for: {address}'
        ban_len = len(header)

        if fmt == 'default':
            print('{}\n{:-<{ban_len}}'.format(header,'',ban_len=ban_len))

        protocol_printer(protocols,address=address,fmt=formats[fmt])

    return 0
