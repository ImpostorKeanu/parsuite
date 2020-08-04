from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
import argparse
import os
import re

help='''IPv4 ONLY! Accept a list of sockets and output three files: 
unique list of IP addresses, unique list of ports, unique list of fqdns
'''


args = [
    DefaultArguments.input_files,
    Argument('--stdout',
        action='store_true',
        help='Dump output to stdout as well'),
    Argument('--base-output-name','-bn',
        required=True,
        help='Base name of the output files'),
    Argument('--csv',
        action='store_true',
        help='Return values as comma separated')
]

def parse(input_files=None, base_output_name=True, csv=False, stdout=False, **kwargs):

    bon = base_output_name
    dct = {}
    dct['ips'], dct['fqdns'], dct['ports'] = [], [], []

    # =====================
    # PARSE EACH INPUT FILE
    # =====================

    for input_file in input_files:

        with open(input_file) as infile:

            for line in infile:

                line = line.strip()

                if not line: continue

                if re.search(r'[A-Za-z]', line): key = 'fqdn'
                else: key = 'ips'

                if re.search(r':',line): addr,port = line.split(':')
                else: addr,port = line,None

                if port and port not in dct['ports']: dct['ports'].append(port)

                if addr not in dct[key]: dct[key].append(addr)

    # ====================
    # DUMP TO OUTPUT FILES
    # ====================

    for k,l in dct.items():

        if not l: continue

        fname = base_output_name+'_'+k

        if csv: fname += '.csv'
        else: fname += '.txt'

        if stdout: esprint(f'Dumping: {k}')

        with open(fname,'w') as outfile:

            if csv:
                if stdout: print(','.join(l))
                outfile.write(','.join(l))

            else:

                for line in l:
                    if stdout: print(line)
                    outfile.write(line+'\n')

    esprint('Finished!')
