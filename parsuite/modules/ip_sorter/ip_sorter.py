from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
from sys import exit,stderr,stdout
import re
from netaddr import *
from sys import exit

help='Sort IPv4 networks and addresses.'

args = [
    DefaultArguments.input_files_optional,
    Argument('--values','-rs',
        default=[],
        nargs='+',
        help='IP/network values.'),
    DefaultArguments.output_file_stdout_default
]

networks, addresses = [], []

def ipInNetworks(value) -> bool:
    '''Determine if an IP address falls within currently known networks
    '''

    for network in networks:
        if value in network: return True

    return False

def handleValue(value) -> None:
    '''Parse a value and add it to the networks or addresses list. Either
    a CIDR or IP address value can be supplied. Nothing is returned and
    all parsed values are stored in the global variables `networks` and
    `addresses`.
    '''

    # Parse the value into an IPNetwork
    try:
        value = IPNetwork(value)
    except Exception as e:
        esprint(f'Failed to parse Network/IP value: {value}')
        return

    # If it's an address, then a 32 bet netmask is returned. We check
    # the integer value here for efficiency
    is_address = True if int(value.netmask) == 4294967295 else False

    # Capture addresses only when it has not already been captured or
    # when it does not fall into a currently known network
    if is_address and not value in addresses \
            and not ipInNetworks(value.ip):
        addresses.append(value.ip)

    # Capture new networks
    elif not is_address and not value in networks:
        networks.append(value)

        # Remove any address values that fall within the newly added range
        ind = 0
        while ind < len(addresses):
            if addresses[ind] in value: del(addresses[ind])
            ind += 1

def loopValues(iterable) -> None:
    '''Loop over each value of an iterable object and pass it to
    handleValue.
    '''

    is_file = not isinstance(iterable,list)
    for v in iterable:
        if is_file: v = v.strip()
        handleValue(v)

def parse(input_files=[],values=[],output_file=stdout,*args, **kwargs):

    # Expand addresses at the commandline
    if values: esprint('Iterating commandline values')
    for value in values:
        loopValues(values)

    # Expand addresses in each input file
    if input_files: esprint('Iterating input files')
    for fname in input_files:

        esprint(f'Expanding ranges in {fname}')
        
        # Open the file and expand each network
        with open(fname) as infile:
            loopValues(infile)

    # ===============
    # DUMP THE OUTPUT
    # ===============

    final = sorted(networks+addresses)

    # To a file
    if output_file == stdout:
        esprint('Writing sorted output to stdout')
        for v in final: print(str(v))

    # To stdout
    else:
        esprint(f'Writing output to {output_file}')
        with open(output_file) as outfile:
            outfile.write(str(v)+'\n')

    return 0
