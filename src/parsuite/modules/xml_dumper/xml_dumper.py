from parsuite.core.argument import (
    Argument,
    DefaultArguments,
    ArgumentGroup,
    MutuallyExclusiveArgumentGroup)
from parsuite import helpers
from parsuite.core.suffix_printer import *
from parsuite.parsers.nmap import (
    parse_nmap,
    parse_http_links as parse_nmap_links)
from parsuite.parsers.nessus import (
    parse_nessus,
    parse_http_links as parse_nessus_links)
from parsuite.parsers.masscan import parse_masscan
from sys import stderr,exit
import lxml.etree as ET
import argparse
import os
import pdb
import csv

from IPython import embed

class CSVList(list):

    def write(self,value):
        self.append(value)


help='''Dump hosts and open ports from multiple masscan, nmap,
or nessus files. A generalized abstraction layer is used to
produce objects that align with the Nmap XML structure since
it has the most comprehensive XSD file.
'''

args = [
    DefaultArguments.input_files,
    Argument('--delimiter','-d',
        default='\n',
        type=str,
        help='''String delimiter used for each line of output.
        Default: newline (\\n)
        '''),
    Argument(
        '--format','-f',
        default='address',
        choices=sorted(['socket','address','uri','port','san_dns_name','service','hostport']),
        help='''Output format. Default: %(default)s'''),
    Argument(
        '--transport-layer','-tl',
        action='store_true',
        help='''When printing URIs, use the transport layer for
        the scheme component, e.g. tcp instead of http'''
    ),
    Argument(
        '--all-addresses',
        action='store_true',
        help='''Return IPs and FQDNs. Default: %(default)s'''),
    Argument(
        '--fqdns',
        action='store_true',
        help='''Return FQDNs instead of ip addresses. Default: 
        %(default)s'''),
    Argument(
        '--port-required',
        action='store_true',
        help='''Return hosts only when they have at least one port open.
        Default: %(default)s
        '''),
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
    Argument(
        '--extrainfo','-e',
        action='store_true',
        help='''Display extra info, such as service versions.
        Supported output formats: URI, Sockets.
        '''
    ),
    Argument(
        '--service-search',
        nargs='+',
        help='''Search services for a string. Default: %(default)s
        '''),
    Argument(
        '--http-links',
        action='store_true',
        help='''Mangle and return only links for HTTP services. Will attempt
        to create individual links for all observed hostnames EXCEPT SAN values
        in certificates. Note that this flag is not available for Masscan output
        since it does not perform service scanning. Default: %(default)s.
        '''),
    Argument(
        '--protocols',
        nargs='+',
        default=['tcp'],
        choices=['tcp','udp','sctp','ip'],
        help='''Transport layer protocols to dump: tcp, udp, sctp, ip. Note 
        that not all file formats support all protocols.
        Default: %(default)s''')
]

PLURAL_MAP = {'address':'addresses',
        'hostport':'hostports',
        'socket':'sockets',
        'uri':'uris',
        'port':'ports',
        'san_dns_name':'san_dns_names',
        'service':'services'}

def parse(input_files, format, all_addresses, fqdns, 
        port_required, port_search, service_search, protocols,
        transport_layer, delimiter, http_links, sreg, extrainfo,
        *args, **kwargs):

    format = PLURAL_MAP[format]

    # ======================
    # HANDLE LINK GENERATION
    # ======================

    if http_links:

        esprint('Parsing HTTP links')

        # TODO: Update this when lxml has been normalized across all parser
        links = []
        for input_file in input_files:

            try:
                tree = ET.parse(input_file)
                f = fingerprint = helpers.fingerprint_xml(tree)
                if not f:
                    esprint(f'Unknown document provided: {input_file}')
                if not f in ['nessus','nmap']:
                    esprint(f'Unsupported document provided: {input_file}')
                else:
                    esprint(f'Dumping {f} file: {input_file}')
                    links += globals()[f'parse_{f}_links'](
                        tree, *args, **kwargs
                    )
    
            except Exception as e:
                esprint(f'Unhandled exception occurred while parsing: {input_file}')
                print('\n'+e.__str__()+'\n')
    
        print('\n'.join(list(set(sorted(links)))))
    
        return 0

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

    # host objects organized by address
      # {address:Host}
    final_report = {}
    for input_file in input_files:

        try:
            esprint(f'Parsing: {input_file}')
            tree = ET.parse(input_file)
        except (Exception,AssertionError) as e:
            esprint(f'Failed to parse: {input_file}\n\n{e}\n\nSkipping...')
            continue

        fingerprint = helpers.fingerprint_xml(tree)

        # Reference to globas is a means of getting a handle on the appropriate
        # class to perform parsing.
        for address,host in globals() \
                ['parse_'+fingerprint] \
                (tree, port_required).items():

            if not address in final_report:
                final_report[address] = host
            else:
                for port in host.ports:
                    final_report[address].append_port(port)

    # ==========================
    # DUMP THE RESULTS TO STDOUT
    # ==========================

    # Build the appropriate output
    output = []
    for address, host in final_report.items():
        output += host.__getattribute__('to_'+format)(
            fqdns=fqdns,
            open_only=True,
            protocols=protocols,
            scheme_layer=scheme_layer,
            port_search=port_search,
            service_search=service_search,
            sreg=sreg,
            extrainfo=extrainfo,)
    
    # Format and dump the output
    if format == 'ports':

        print(delimiter.join([str(p) for p in sorted(set(output))]))

    elif format == 'services':

        csv_output = CSVList()
        writer = csv.writer(csv_output)
        writer.writerow([
            'socket', 'protocol', 'service_name', 'service_product',
            'service_version','service_extrainfo'
        ])
        for row in output: writer.writerow(row)
        print(''.join(csv_output))

    elif format == 'san_dns_names':

        print(delimiter.join(sorted(list(set(output)))))

    else:

        print(delimiter.join(output))

    return 0
