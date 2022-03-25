from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
from publicsuffix2 import get_public_suffix
from sys import exit,stderr,stdout
import re
from netaddr import *
from sys import exit

help='Extract apex domains from a list of FQDNs.'

args = [
    DefaultArguments.input_files_optional,
    Argument('--values','-rs',
        default=[],
        nargs='+',
        help='IP/network values.'),
    DefaultArguments.output_file_stdout_default
]

def handleValue(value:str) -> str:

    out = None
    try:
        out = get_public_suffix(value.strip())
    except Exception as e:
        print(f'Failed to parse value: {value} > {e}')

    return out
        
def parse(input_files=None, values=None, output_file=stdout, *args, **kwargs):

    input_files = [] if not input_files else input_files
    values = [] if not values else values
    apexes = []

    # Expand addresses at the commandline
    if values: esprint('Iterating commandline values')
    for value in values:
        value = handleValue(value)
        if value:
            apexes.append(value)

    # Expand addresses in each input file
    if input_files: esprint('Iterating input files')
    for fname in input_files:

        esprint(f'Extracting apex domains from {fname}')
        
        # Open the file and expand each network
        with open(fname) as infile:
            for value in infile:
                value = handleValue(value)
                if value:
                    apexes.append(value)

    # ===============
    # DUMP THE OUTPUT
    # ===============

    apexes = sorted(set(apexes))

    # To a file
    if output_file == stdout:
        esprint('Writing output to stdout')
        for v in apexes: print(str(v))

    # To stdout
    else:
        esprint(f'Writing output to {output_file}')
        with open(output_file) as outfile:
            for v in apexes:
                outfile.write(str(v)+'\n')

    return 0
