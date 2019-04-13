from parsuite.core.argument import Argument,DefaultArguments,ArgumentGroup,MutuallyExclusiveArgumentGroup
from parsuite import helpers
from parsuite.core.suffix_printer import *
from sys import stderr
import xml.etree.ElementTree as ET
import argparse
import os

help='Dump hosts and open ports from a masscan xml file.'

formats={
    'default':'{protocol}/{port}',
    'proto_socket':'{protocol}://{address}:{port}',
    'socket':'{address}:{port}'
}

args = [
    DefaultArguments.input_file,
    MutuallyExclusiveArgumentGroup(
        required=True,
        arguments=[
            Argument('--fmt','-f',choices=list(formats.keys()),
                default='default'),
            Argument('--custom-format','-cf',action='store',
                dest='fmt',
                help='Format the output to your needs using the '\
                'following syntax: "{keyword}". The following '\
                'keywords are available: protocol, address, and port. '\
                'Provide one more more keyword. Example (socket): '\
                '"{address}:{port}"')
        ]
    )
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

def parse(input_file=None, fmt=None, custom_format=None, *args, **kwargs):

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

    if not fmt in formats:
        fmt = fmt
    else:
        fmt=formats[fmt]

    try:

        for address,protocols in report.items():
            
            header = f'Open ports for: {address}'
            ban_len = len(header)
    
            if fmt == formats['default']:
                print()
                print('{}\n{:-<{ban_len}}'.format(header,'',ban_len=ban_len))
    
            protocol_printer(protocols,address=address,fmt=fmt)

    except KeyError as error:

        print('\nKeyError occurred. This indicates that an invalid keyword has been'\
            ' supplied for formatting. See --help.',
            file=stderr)
        sprint('Only the following keywords are available for formatting:'\
            ' protocol, address, port')
        print()

    return 0
