from parsuite.core.argument import Argument,DefaultArguments
from parsuite.abstractions.xml.generic import network_host as NH
from parsuite import helpers
from parsuite.core.suffix_printer import *
#import xml.etree.ElementTree as ET
from lxml import etree as ET
import argparse
import os
import re

help='Accept a XML file generated '\
     'by Nmap and write SSL certificate information to stdout'

args = [
    DefaultArguments.input_file,
]

def parse(input_file=None, renegade_parse=None, **kwargs):


    # parse the input file
    tree = ET.parse(input_file)

    scripts = tree.xpath('//host/ports/port/script[@id="ssl-cert"]')

    if not scripts:
        esprint('No ssl-cert script results found in XML file!')

    for script in scripts:

        address = script.xpath('../../../address')[0].get('addr')

        for line in script.get('output').split('\n'):

            if re.match(r'^Subject',line,re.I):
                
                line = re.sub(r"(Subject|Subject Alternative Name): ","",line) 
                print(f'{address}:{line}')

    return 0
