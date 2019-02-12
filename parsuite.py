#!/usr/bin/python3.6

import argparse
import os
from pathlib import Path
from sys import exit, modules as sys_modules

from parsuite import modules
from parsuite import helpers
from parsuite.core.suffix_printer import *
from parsuite.core.argument import Argument

if __name__ == '__main__':

    ap = argument_parser = argparse.ArgumentParser(
        description='Parse the planet.')

    ap.add_argument('--input-file', '-if', required=True)

    subparsers = ap.add_subparsers(help='Parser module selection.')
    subparsers.required = True
    subparsers.dest = 'module'

    print()
    sprint('Starting the parser\n')
    # strap arguments from modules as argument groups
    sprint('Loading modules')
    for handle,module in modules.handles.items():

        helpers.validate_module(module)
        sub = subparsers.add_parser(handle,help=module.help)

        for arg in module.args:
            sub.add_argument(*arg.pargs, **arg.kwargs)

    args = ap.parse_args()
    
    # testing inputfile
    assert Path(args.input_file).exists(), (
        'Input file does not exist.'
    )

    sprint(f'Executing module: {args.module}')

    modules.__dict__[args.module].parse(
        **vars(args)
    )
    
    print()
    sprint('Module execution complete. Exiting.')
    print()
