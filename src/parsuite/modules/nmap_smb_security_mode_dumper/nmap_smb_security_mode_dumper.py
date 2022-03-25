from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
import xml.etree.ElementTree as ET
import argparse
import os

help='Dump hosts to a file containing the security mode discovered by '\
    'smb-security-mode.'

args = [
    DefaultArguments.input_file,
    Argument('--output-file', '-of', required=True,
        help='Output file.')
]

def parse(input_file=None, output_file=None, **kwargs):

    # parse the input file
    tree = ET.parse(input_file)

    hosts = tree.findall('.//host/hostscript/script[@id="smb-security-mode"]/../..')

    sprint(f'Parsing {len(hosts)} hosts...\n')
    output = []
    for host in hosts:
        
        elem = host.find(
            './hostscript/script[@id="smb-security-mode"]/elem[@key="message_signing"]'
        )


        if elem != None:
            addr = host.find('./address').attrib['addr']
            elem = elem.text
            output.append(f'{addr}:{elem}')

    sprint('All hosts parsed. Writing output to disk.')
    with open(output_file, 'w') as outfile:

        for l in output:
            outfile.write(l+'\n')

    sprint('Finished!')

    return 0
