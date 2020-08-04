from parsuite.core.argument import Argument
from parsuite import helpers
from parsuite.core.suffix_printer import *
from pathlib import Path
import xml.etree.ElementTree as ET
import argparse
import os
import re

help = 'Convert URLCrazy output to CSV'

args = [
    Argument('--output-file', '-of', required=True,
        help='Output file.')
]

ppat = prefix_pattern = re.compile('^(Bit Flipping|Character Insertion|Character Omission|'\
        'Character Repeat|Character Replacement|Character Swap|Homoglyphs|Homophones|'\
        'Missing Dot|Singular or Pluralise|Vowel Swap|Wrong TLD)')

def parse(input_file=None, output_file=None, **kwargs):

    sprint('Parsing URLCrazy file')
    output = ['"Typo Type","Typo","DNS-A","CC-A","DNS-MX","Extn"']
    with open(input_file) as infile:

        for line in infile:

            if re.search(ppat,line):
                
                output.append('"'+re.sub('\s{2,}','","',line.strip())+'"')

    sprint('Writing output file')
    with open(output_file,'w') as outfile:

        for line in output:

            outfile.write(line+'\n')

    sprint('Done!')

    return 0
