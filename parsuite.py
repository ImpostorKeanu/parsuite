#!/usr/bin/env python3

import argparse
import os
from pathlib import Path
from sys import exit, modules as sys_modules
from re import search

from parsuite import modules
from parsuite import helpers
from parsuite.core.suffix_printer import *
from parsuite.core.argument import (Argument,ArgumentGroup,
    MutuallyExclusiveArgumentGroup)

def add_args(dst_obj,args):
    '''Add arguments to a parser object. Useful when initializing
    an argument group.
    '''

    for arg in args:
        dst_obj.add_argument(*arg.pargs, **arg.kwargs)

if __name__ == '__main__':

    ap = argument_parser = argparse.ArgumentParser(
        description='Parse the planet.')

    subparsers = ap.add_subparsers(help='Parser module selection.')
    subparsers.required = True
    subparsers.dest = 'module'
    esprint('Starting the parser')
    # strap arguments from modules as argument groups
    esprint('Loading modules')

    sub = subparsers.add_parser('module_table',
        help='Dump module table in Markdown (for documentation)')

    for handle,module in modules.handles.items():

        helpers.validate_module(module)
        sub = subparsers.add_parser(handle,help=module.help)

        for arg in module.args:

            if arg.__class__ == ArgumentGroup:

                group = sub.add_argument_group(*arg.pargs, **arg.kwargs)
                add_args(group,arg)

            elif arg.__class__ == MutuallyExclusiveArgumentGroup:


                group = sub.add_mutually_exclusive_group(
                    *arg.pargs, **arg.kwargs
                )
                add_args(group,arg)

            else:

                sub.add_argument(*arg.pargs, **arg.kwargs)

    args = ap.parse_args()
    
    if args.module == 'module_table':

        print('|Module|Description|\n|--|--|')
        for handle,module in modules.handles.items():
            h = ' '.join(module.help.strip().split('\n'))
            print(f'|{handle}|{h}|')
        exit()           
            
    if 'input_file' in args:
        helpers.validate_input_file(args.input_file)
    elif 'input_files' in args:
        helpers.validate_input_files(args.input_files)


    esprint(f'Executing module: {args.module}')

    modules.handles[args.module].parse(
        **vars(args)
    )
    
    esprint('Module execution complete. Exiting.')
