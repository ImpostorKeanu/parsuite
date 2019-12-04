from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
from parsuite.abstractions.xml.burp import *
from lxml import etree as ET
import argparse
import os
from sys import stdout, exit


help = '''Input an XML file containing Burp items and dump each 
transaction to a directory.'''

args = [
    DefaultArguments.input_file,
    Argument('--output-directory', '-od', required=True,
        help='Output directory.'),
]

def parse(input_file=None, output_directory=None, **kwargs):

    esprint(f'Parsing input file: {input_file}')
    

    # parse the input file as HTML
    tree = ET.parse(input_file)
    
    bo = base_output_path = helpers.handle_output_directory(
        output_directory
    )
    os.chdir(bo)

    counter = 0

    for item in tree.xpath('//item'):

        try:

            item = Item.from_lxml(item)

        except Exception as e:

            esprint(f'Failed to parse item #{counter}: {e}')
            continue

        with open(str(counter)+'.req','w') as outfile:

            outfile.write(
                f'URL: {item.url}\r\n{item.request.firstline}\r\n'
            )

            for k,v in item.request.headers.items():
                outfile.write(
                    f'{k}: {v}\r\n'
                )

            outfile.write('\r\n\r\n')
            outfile.write(item.request.sbody)
        
        if item.mimetype: mimetype = item.mimetype.lower()
        else: mimetype = 'no_mimetype'

        with open(str(counter)+'.resp.'+mimetype,'w') as outfile:
            
            outfile.write(
                f'URL: {item.url}\r\n{item.response.firstline}\r\n'
            )

            for k,v in item.response.headers.items():
                outfile.write(
                    f'{k} {v}\r\n'
                )

            outfile.write('\r\n\r\n')
            outfile.write(item.response.sbody)
        
        counter += 1

    return 0
