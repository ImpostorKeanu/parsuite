from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
from sys import exit,stderr,stdout
import re
from base64 import b64encode
from pathlib import Path

help='''Base64 encode a series of values or contents of files. WARNING:
 files are slurped and encoded as a whole.
'''


args = [
    Argument('--values','-vs',
        required=True,
        nargs='+',
        help='''String or files to encode.
        '''),
    Argument('--delimiter','-d',
        help='''Character or string to join each encoded value on.
        Supplying a value to this character results in all values
        being concatenated and returned as a whole.'''
    )
        
]

def encode(v):

    return b64encode(bytes(v,'utf-8')).decode('utf-8')

def parse(values,delimiter,*args, **kwargs):

    ind = 0

    while ind < values.__len__():

        if Path(values[ind]).exists():
            esprint(f'Encoding file: {values[ind]}')
            with open(values[ind]) as infile:
                values[ind] = encode(infile.read())
        else:
            esprint(f'Encoding value: {values[ind]}')
            values[ind] = encode(values[ind])

        ind += 1


    if not delimiter:

        for v in values:
            print(v)

    else:

        esprint('Printing delimited value:')
        print(delimiter.join(values))

    return 0
