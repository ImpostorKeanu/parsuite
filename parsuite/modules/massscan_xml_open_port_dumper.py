from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
import xml.etree.ElementTree as ET
import argparse
import os

help='Dump hosts and open ports from a masscan xml file.'

args = [
    DefaultArguments.input_file,
]

def parse(input_file=None, **kwargs):

    report = {}

    # parse the input file
    tree = ET.parse(input_file)
    for host in tree.findall(
        './/host/ports/port/state[@state="open"]../../..'):
        
        address = host.find('address').get('addr')
        ports = {}

        for port in host.findall('.//port/state[@state="open"]..'):

            protocol = port.get('protocol')
            portid = port.get('portid')
            state = port.find('state').get('state')

            if protocol not in ports:
                ports[protocol] = {state:[int(portid)]}

        report[address] = ports

    for address,protocols in report.items():
        
        header = f'Open ports for: {address}'
        ban_len = len(header)
        print('{}\n{:-<{ban_len}}'.format(header,'',ban_len=ban_len))


        for protocol,states in protocols.items():

            for state,ports in states.items():

                if state != 'open':
                    continue

                for port in ports:
                    print(f'{protocol}/{port}')

        print()


    return 0
