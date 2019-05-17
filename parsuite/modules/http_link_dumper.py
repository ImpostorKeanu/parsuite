from parsuite.core.argument import Argument,DefaultArguments
from parsuite.parsers.nmap import parse_http_links as parse_nmap
from parsuite.parsers.nessus import parse_http_links as parse_nessus
from parsuite import helpers
from parsuite.core.suffix_printer import *
import lxml.etree as ET
import argparse
from re import search

help='Parse either an NMAP or Nessus XML file (.nessus) and dump http '\
    'links relative to port and service. The module will determine if '\
    'the input file is Nessus or NMAP by querying the document for a '\
    '`policyName` element, which indicates a Nessus file. All links '\
    'are printed to stdout.'

args = [
    DefaultArguments.input_files,
]

def parse(input_files=None, *args, **kwargs):

    links = []

    for input_file in input_files:

        try:
            tree = ET.parse(input_file)
            fingerprint = helpers.fingerprint_xml(tree)
            if not fingerprint:
                esprint(f'Unknown document provided: {input_file}')
            else:
                esprint(f'Dumping {fingerprint} file: {input_file}')
                links += globals()['parse_'+fingerprint](
                    tree, *args, **kwargs
                )

        except Exception as e:
            esprint(f'Unhandled exception occurred while parsing: {input_file}')
            print('\n'+e.__str__()+'\n')

    print('\n'.join(list(set(sorted(links)))))

    return 0
