from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
from parsuite.abstractions.xml.burp import *
from lxml import etree as ET
import argparse
import os
from sys import stdout, exit
import pdb
from IPython import embed
import jsbeautifier
import re


help = '''Input an XML file containing Burp items and dump each 
transaction to a directory.'''

args = [
    DefaultArguments.input_file,
    Argument('--output-directory', '-od', required=True,
        help='Output directory.'),
    Argument('--no-url',
        action='store_true',
        help='Suppress writing URL to file. Default: False'),
    Argument('--no-headers',
        action='store_true',
        help='Suppress writing headers to file. Default: False'),
    Argument('--no-beautify-js',
        action='store_true',
        help='Suppress JS beautification.. Default: False'),
    Argument('--huge-tree',
        action='store_true',
        help='Enable parsing of large files. Default: False'),
]

def bytify(s,encoding="utf8"):
    return bytes(s,encoding)

def parse(input_file=None, no_url=False, output_directory=None,
        no_headers=False, no_beautify_js=False, huge_tree=False,
        **kwargs):

    # Invert flags
    write_url = (not no_url)
    write_headers = (not no_headers)
    beautify_js = (not no_beautify_js)

    esprint(f'Parsing input file: {input_file}')

    # parse the input file as HTML
    parser = ET.XMLParser(huge_tree=huge_tree)

    try:
        tree = ET.parse(input_file,parser=parser)
    except Exception as e:
        if e.msg.find('Huge input lookup') > 0:
            esprint(
                '\nWARNING: ' \
                'Large input file selected. Include --huge-tree ' \
                'to continue parsing the target file. Exiting.',
                suf='[!]'
            )
            exit()
    
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

        # ==================
        # HANDLE THE REQUEST
        # ==================


        with open(str(counter)+'.req','wb') as outfile:

            if write_url:
                outfile.write(
                    bytify(f'URL: {item.url}\r\n{item.request.firstline}\r\n')
                )

            for k,v in item.request.headers.items():

                if beautify_js \
                        and re.match('content-type',k,re.I) \
                        and re.search('json',v,re.I):
                    try:
                        item.request.sbody = jsbeautifier.beautify(item.request.sbody)
                    except Exception as e:
                        esprint('Failed to beautify JSON: {e}')

                if write_headers: outfile.write(bytify(f'{k}: {v}\r\n'))

            if write_headers: outfile.write(b'\r\n')

            if item.request.body and not item.request.sbody:
                outfile.write(item.request.body)
            else:
                outfile.write(bytify(item.request.sbody))
        
        if item.mimetype: mimetype = item.mimetype.lower()
        else: mimetype = 'no_mimetype'

        # ===================
        # HANDLE THE RESPONSE
        # ===================

        with open(str(counter)+'.resp.'+mimetype,'wb') as outfile:
            
            # Write the first line
            if write_url:
                outfile.write(
                    bytify(f'URL: {item.url}\r\n{item.response.firstline}\r\n')
                )

            # Handle response headers
            for k,v in item.response.headers.items():

                # Beautify JavaScript/JSON content
                if beautify_js \
                        and re.match('content-type',k,re.I) \
                        and re.search('java|json',v,re.I):
                    try:
                        item.response.sbody = jsbeautifier.beautify(item.response.sbody)
                    except Exception as e:
                        esprint('Failed to beautify JavaScript/JSON: {e}')
                        pass

                # Write headers to the output file
                if write_headers: outfile.write(bytify(f'{k}: {v}\r\n'))


            # Write newlines
            if write_headers: outfile.write(b'\r\n')

            # Write response body to disk
            if item.response.body and not item.response.sbody:
                outfile.write(item.response.body)
            else:
                outfile.write(bytify(item.response.sbody))
        
        counter += 1

    return 0
