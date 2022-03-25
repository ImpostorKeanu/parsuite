from parsuite.core.argument import Argument,DefaultArguments,ArgumentGroup,MutuallyExclusiveArgumentGroup
from parsuite import helpers
from parsuite.core.suffix_printer import *
import json
from sys import stderr,exit,stdout
import pdb

help='Pretty print a JSON object to stdout.'

args = [
    DefaultArguments.input_file,
    Argument('--indent','-i',
        default=4,
        type=int,
        help='Indent level. Default: %(default)s')
]

def parse(input_file, indent, *args, **kwargs):

    with open(input_file) as i:

        j = json.load(i)
        json.dump(j,stdout,indent=indent)

    return 0
