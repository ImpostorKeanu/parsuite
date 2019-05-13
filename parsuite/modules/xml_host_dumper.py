from parsuite.core.argument import Argument,DefaultArguments,ArgumentGroup,MutuallyExclusiveArgumentGroup
from parsuite import helpers
from parsuite.core.suffix_printer import *
from parsuite.parsers.nmap import parse_nmap
from parsuite.parsers.nessus import parse_nessus
from parsuite.parsers.masscan import parse_masscan
from sys import stderr,exit
import xml.etree.ElementTree as ET
import argparse
import os

help='''Dump hosts and open ports from multiple masscan, nmap,
or nessus files. A generalized abstraction layer is used to
produce objects that align with the Nmap XML structure since
it has the most comprehensive XSD file.
'''

args = [
    DefaultArguments.input_files,
    # TODO
    Argument('--delimiter','-d',
        default='\n',
        type=str,
        help='''String delimiter used for each line of output.
        Default: newline (\\n)
        '''),
    # TODO
    Argument(
        '--format','-f',
        required=True,
        choices=['sockets','addresses','uris','address-ports','ports'],
        help='''Output format. Default: %(default)s'''),
    Argument(
        '--transport-layer','-tl',
        action='store_true',
        help='''When printing URIs, use the application layer for
        the scheme component, e.g. tcp instead of http'''
    ),
    # TODO
    Argument(
        '--all-addresses',
        action='store_true',
        help='''Return IPs and FQDNs. Default: %(default)s'''),
    # TODO
    Argument(
        '--fqdns',
        action='store_true',
        help='''Return FQDNs instead of ip addresses. Default: 
        %(default)s'''),
    # TODO
    Argument(
        '--port-required',
        action='store_true',
        help='''Return hosts only when they have at least one port open.
        Default: %(default)s
        '''),
    # TODO
    Argument(
        '--port-search',
        nargs='+',
        default=[],
        type=int,
        help='''Return hosts only when they have matching open ports.
        Default: %(default)s
        '''),
    Argument(
        '--sreg','-pr',
        action='store_true',
        help='''Treat service searches as individual regexes.'''
    ),
    # TODO
    Argument(
        '--service-search',
        nargs='+',
        help='''Search services for a string. Default: %(default)s
        '''),
    # TODO
    Argument(
        '--mangle-http',
        action='store_true',
        help='''Mangle HTTP services into an HTTP/HTTPS link.
        Default: %(default)s
        '''),
    # TODO
    Argument(
        '--protocols',
        nargs='+',
        default=['tcp'],
        choices=['tcp','udp','sctp','ip'],
        help='''Protocols to dump: tcp, udp, sctp, ip. Note that not all
        file formats support all protocols. Default: %(default)s''')
]

class Report(dict):
    
    def aggregate(self,report):
        '''Aggregate another report with this report. Note that
        ports and other objects associated with a given host
        will be overwritten with the most current one provided
        in given report.
        '''

        rclass = report.__class__
        if rclass != Report and rclass != Report:
            raise TypeError(
                'report argument must be a dict or report'
            )

        for address,host in report:
            if address not in self:
                self[address] = host
            else:
                for port in host.portlist:
                    self[address].append_port(port)

    def query_addresses(self,port_required=True,port_search=[],
            service_search=None,protocols=['tcp'],*args,**kwargs):
        '''Extract addresses from the report.
        '''
       
        #TODO: Pick up here!
        output = []

    def query_sockets(self,port_required=True,port_search=[],
            service_search=None,protocols=['tcp'],*args,**kwargs):
        '''Extract addresses from the report.
        '''
        pass

    def query_uris(self,port_required=True,port_search=[],
            service_search=None,protocols=['tcp'],mangle_http=False,
            *args,**kwargs):
        '''Extract addresses from the report.
        '''
        pass

def parse(input_files, format, all_addresses, fqdns, 
        port_required, port_search, service_search,
        mangle_http, protocols, transport_layer,
        delimiter, sreg, *args, **kwargs):

    # ==========================
    # NEGOTIATE THE SCHEME LAYER
    # ==========================

    if format == 'uris':
        if transport_layer: scheme_layer = 'transport'
        else: scheme_layer = 'application'
    else:
        scheme_layer = False

    # ==============================================
    # PARSE EACH INPUT FILE INTO A REPORT DICTIONARY
    # ==============================================

    final_report = {}
    for input_file in input_files:
        
        tree = ET.parse(input_file)
        fingerprint = helpers.fingerprint_xml(tree)
        for address,host in globals()['parse_'+fingerprint](tree,port_required) \
            .items():
            if not address in final_report:
                final_report[address] = host
            else:
                for port in host.ports:
                    final_report[address].append_port(port)

    # ==========================
    # DUMP THE RESULTS TO STDOUT
    # ==========================

    output = []
    for address,host in final_report.items():
        output += host.__getattribute__('to_'+format)(
            fqdns=fqdns,
            open_only=True,
            protocols=protocols,
            scheme_layer=scheme_layer,
            port_search=port_search,
            service_search=service_search,
            sreg=sreg,
        )
    print(delimiter.join(output))

    return 0
