from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
import xml.etree.ElementTree as ET
import argparse
from sys import exit,stdout
from datetime import datetime
from base64 import b64encode
import json
import pdb

help = '''Parse cookies from the results table of a Burp Intruder attack
and translate them to an Authmatrix state file for those users. Warning:
 This tool assumes that the username is in Payload1. Also make sure that
 invalid records are removed from the table file, otherwise they will
 be translated as well.
'''

args = [
    DefaultArguments.input_files,
    Argument('--delimiter','-d',
        default='\t',
        help='Delimiter that separates values. Default: \\t (tab character)'),
    Argument('--payload-number','-pn',
        default='1',
        help='''Payload number containing the username. You can get
        this value by looking at the output table and mapping the
        column header to the username values.
        '''),
    Argument('--pretty-print','-pp',
        action='store_true',
        help='Pretty print the results.'),
]

def encode(s):
    return b64encode(bytes(s,'utf8')).decode('utf8')

def parse(input_files=None, delimiter='\t', payload_number=1,
        pretty_print=None, **kwargs):

    if pretty_print: pretty_print=4
    else: pretty_print=None 

    counter = 0
    dct = {
            'version':'0.8',
            'arrayOfUsers': []
    }

    for input_file in input_files:

        # =======================
        # PREPARE INPUT FROM FILE
        # =======================

        # Parse each record while splitting on the delimiter and
        # stripping newlines
        with open(input_file) as infile:
            records=[r.strip().split(delimiter) for r in infile]

        headers,records = records[0],records[1:]

        # ====================================
        # PARSE EACH RECORD INTO A USER OBJECT
        #=====================================
        
        payload_header = f'Payload{payload_number}'
        offset = 0
        username_offset,cookie_offset = 0,0

        # Determine the offset to each target value
        # - username_offset indicates where the username value is
        # - cookie_offset indicates where the cookie value is
        for header in headers:
            if header == payload_header:
                username_offset = offset
            elif header == 'Cookies':
                cookie_offset = offset
            
            if username_offset and cookie_offset: break
            offset += 1

        # =================
        # PARSE THE RECORDS
        # =================

        for record in records:
            try:
                username = record[username_offset]
                cookies = encode(record[cookie_offset])
            except:
                esprint(f'Invalid record: {record}')
                continue

            dct['arrayOfUsers'].append(
                    {
                        'name':username,
                        'index':counter,
                        'tableRow':counter,
                        'cookiesBase64':cookies,
                        'headersBase64':[],
                        'roles':{}
                    }
            )
            counter += 1

        print(json.dumps(dct,indent=pretty_print))

    return 0
