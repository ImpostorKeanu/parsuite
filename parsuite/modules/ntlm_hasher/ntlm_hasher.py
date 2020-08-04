from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
import hashlib,binascii
import argparse
import os
import re

help='NTLM hash a value.'

args = [
    Argument('--value','-v',
        required=True,
        help='Value to hash.'
    )
]

def parse(value=None, *args, **kwargs):

    esprint(f'Hashing {value}')
    print(str(binascii.hexlify(
        hashlib.new('md4',value.encode('utf-16le')).digest())
    ,'utf-8'))
