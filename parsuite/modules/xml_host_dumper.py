from parsuite.core.argument import Argument,DefaultArguments,ArgumentGroup,MutuallyExclusiveArgumentGroup
from parsuite import helpers
from parsuite.core.suffix_printer import *
from sys import stderr,exit
import xml.etree.ElementTree as ET
import argparse
import os

'''
# Universal Parser to Extract IPs & Sockets

0. Parse the file into an etree object
0. Determine format
0. Pass etree to appropriate parse function

'''

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

def parse_nmap(tree,no_services):
    
    report = {}

    # Capture hosts with listening services
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
            elif not state in ports[protocol]:
                ports[protocol][state] = [int(portid)]
            elif not int(portid) in ports[protocol][state]:
                ports[protocol][state].append(int(portid))

        report[address] = ports

    # Capture hosts with no listening services
    if no_services:
        for host in tree.findall('.//host/status[@state="up"]/..'):
            status = host.find('.//status')
            for addr in host.findall('.//address[@addrtype="ipv4"]'):
                if addr not in report:
                    report[addr.attrib['addr']] = {'no-service':{'alive':[status.attrib['reason']]}}
                else:
                    report[addr.attrib['addr']]['no-service']['alive'].append(status.attrib['reason'])

    return report

def parse_nessus(tree,no_services):
    report = {}

    for rhost in tree.findall('.//ReportItem/..'):
        ip = rhost.find('.//tag[@name="host-ip"]')
        if ip == None: ip = rhost.attrib['name']
        else: ip = ip.text

        ports = {}
        for ri in rhost.findall('.//ReportItem'):
            svc_name = ri.get('svc_name')
            protocol = ri.get('protocol')
            port = ri.get('port')
            ports[protocol] = {'open':[int(port)]}

        report[ip] = ports

    return report

def parse_masscan(*args,**kwargs):
    return parse_nmap(*args,**kwargs)

def parse(input_files=None, fmt=None, no_services=None, host_only=False, *args, **kwargs):

    if fmt in formats: fmt = formats[fmt]
    report = {}
    for input_file in input_files:
        
        tree = ET.parse(input_file)
        fingerprint = helpers.fingerprint_xml(tree)
        ireport = globals()['parse_'+fingerprint](tree,no_services)

        # Aggregate host/ports from reports
        # Report structure (shit show):
          # {ip_address: 
          #    {protocol (tcp/ip):
          #        {state (open/closed):[integer_ports]}
          #     }
          # }
          
        # {ip_address: {protocol (tcp/ip): {state:ports}}}
        for ip_address, protocol_struct in ireport.items():

            if not ip_address in report:

                report[ip_address] = protocol_struct

            else:
                
                #    {protocol (tcp/ip): {state:ports}}
                for protocol,port_struct in protocol_struct.items():
                
                    if not protocol in report[ip_address]:

                        report[ip_address][protocol] = port_struct

                    else:

                        report_port_struct = report[ip_address][protocol]

                        # {state:ports}
                        for state,ports in port_struct.items():

                            if not state in report_port_struct:
                                report_port_struct[state] = ports
                            else:

                                for port in ports:

                                    if not port in report_port_struct[state]:
                                        report_port_struct[state].append(port)


    dump(report,fmt,host_only)

    return 0
