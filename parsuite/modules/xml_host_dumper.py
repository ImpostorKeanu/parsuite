from parsuite.core.argument import Argument,DefaultArguments,ArgumentGroup,MutuallyExclusiveArgumentGroup
from parsuite import helpers
from parsuite.core.suffix_printer import *
from parsuite.parsers.nmap import parse_nmap
from sys import stderr,exit
import xml.etree.ElementTree as ET
import argparse
import os

help='Dump hosts and open ports from a masscan xml file.'

formats={
    'default':'{protocol}/{port}',
    'proto_socket':'{protocol}://{address}:{port}',
    'socket':'{address}:{port}',
}

fmt_help = 'Print each host/service to stdout using one of the '\
    'following formats: ' + ', '.join({f'{k}: {v}' for k,v in formats.items()})

args = [
    DefaultArguments.input_files,
    Argument('--no-services', '-ns',
        action='store_true',
        help='Dump hosts that do not have any listening services have.'),
    MutuallyExclusiveArgumentGroup(
        required=True,
        arguments=[
            Argument('--host-only','-ho',
                action='store_true',
                help='Dump unique IP addresses without ports.'),
            Argument('--fmt','-f',choices=list(formats.keys()),
                default='default',
                help=fmt_help),
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

def protocol_printer(protocols,address=None,fmt='{protocol}/{port}'):

    for protocol,states in protocols.items():

        for state,ports in states.items():
    
            for port in ports:
    
                print(
                    fmt.format(address=address,
                        protocol=protocol,
                        port=port)
                )

def dump(report,fmt,host_only):

    if host_only:
        print('\n'.join(report.keys()))
        return

    for address,protocols in report.items():
        
        header = f'Open ports for: {address}'
        ban_len = len(header)

        if fmt == formats['default']:
            print()
            print('{}\n{:-<{ban_len}}'.format(header,'',ban_len=ban_len))

        protocol_printer(protocols,address=address,fmt=fmt)


def parse_masscan(*args,**kwargs):
    return parse_nmap(*args,**kwargs)

def parse(input_files=None, fmt=None, no_services=None, host_only=False, *args, **kwargs):

    if fmt in formats: fmt = formats[fmt]
    report = {}
    for input_file in input_files:
        
        tree = ET.parse(input_file)
        fingerprint = helpers.fingerprint_xml(tree)
        report = globals()['parse_'+fingerprint](tree,no_services)

    for ip,host in report.items():

        if host_only: print(host.to_uris(mangle_http=True))

    return 0
