from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
from sys import exit,stderr,stdout
import re
from sys import exit
import ipaddress

help='Expand a series of IPv4/6 ranges into addresses.'


args = [
    DefaultArguments.input_files_optional,
    Argument('--ranges','-rs',
        default=[],
        nargs='+',
        help='Ranges to expand.'),
    DefaultArguments.output_file_stdout_default
]

def get_network(value):
    '''Expand the supplied network into an interable of
    containing ip address objects.
    '''

    try:

        network = ipaddress.ip_network(value,False)

        if not network:
            raise Exception()

    except:

        esprint(f'Invalid network/address: {value}')
        network = []


    return network

def iterate(addresses,output_file,counter):
    '''Iterate over the iterable produced by get_network
    and write each address to file.
    '''

    for address in addresses:
        counter += 1
        output_file.write(address.exploded+'\n')

    return counter

def parse(input_files=[],ranges=[],output_file=stdout,*args, **kwargs):

    # Keep count of the total number of IP addresses
    counter = 0

    # Negotiate the output file
    if output_file != stdout:
        esprint(f'Writing output to {output_file}')
        output_file = open(output_file,'w')
    else:
        esprint('Dumping addresses to stdout')

    # Besure to close the output file via Finally
    try:

        # Expand addresses at the commandline
        esprint('Expanding command line ranges')
        for value in ranges:

            for value in ranges:
                value = value.strip()
                counter = iterate(
                    get_network(value),
                    output_file,
                    counter
                )

        # Expand addresses in each input file
        for fname in input_files:

            esprint(f'Expanding ranges in {fname}')
            
            # Open the file and expand each network
            with open(fname) as infile:
    
                for value in infile:
                    value = value.strip()
                    counter = iterate(
                        get_network(value),
                        output_file,
                        counter
                    )

    # Close the output file
    finally:

        esprint(f'Finished! Total addresses written: {counter}')
        output_file.close()

    return 0
