from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
import argparse
import os
import re

'''
SAMPLE:

USERNAME::DOMAIN:AAAAAAAAAAAAAAAA:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

'''

help='Stuff'\

args = [
    DefaultArguments.input_files,
    Argument('--unique','-u',
        action='store_false',
        help='Dump only unique username/domain combinations'
    )
]

class NTLMv2:

    def __init__(self,hsh):

        self.__hsh__ = hsh
        split = re.sub('::',':',hsh).split(':')
        self.username = split[0]
        self.domain = split[1]
        self.hash = ':'.join(split[2:])

    def reconstruct(self):

        return self.__hsh__

def parse(input_files=None, unique=True, **kwargs):

    cache = []

    esprint(f'Parsing hash files: {",".join(input_files)}')
    for input_file in input_files:

        with open(input_file) as infile:
            for hsh in infile:
                hsh = NTLMv2(hsh.strip())
                _id = hsh.username+':'+hsh.domain
                if unique and _id in cache:
                    continue
                elif unique:
                    cache.append(_id)
                print(hsh.__hsh__)
    esprint('Finished!')
