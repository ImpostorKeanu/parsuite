from parsuite.core.argument import (Argument,DefaultArguments,
        ArgumentGroup,MutuallyExclusiveArgumentGroup)
from parsuite import helpers
from parsuite.core.suffix_printer import *
from multiprocessing import Pool
import argparse
import os
import re
from time import sleep

help='''Map cleartext passwords recovered from password cracking back 
to uncracked values.'''

args = [
    Argument('--hash-files','-hf',
        required=True,
        nargs='+',
        help='Base file of uncracked hashes'
    ),
    Argument('--output-file','-of',
        required=False,
        help='File to write output.'
    ),
    Argument('--cracked-delimiter','-cd',
        default=':',
        help="""Delimiter that is used to separate the password
        hash from the cleartext value in a cracked hash. Default: ':'
        """
    ),
    # TODO: Finish multiprocessing
#    Argument('--process-count','-pc',
#        default=4,
#        type=int,
#        help='Count of processes to use'
#    ),
    MutuallyExclusiveArgumentGroup(
        required=True,
        arguments=[
            Argument('--cracked-files','-cf',
                nargs='+',
                help="""File containing cracked password hashes. Each
                line should be in the following format:
                <hash><cracked_delimiter><password>
                """
            ),
            Argument('--cracked-hashes','-ch',
                nargs='+',
                help="""A single cracked hash in the following format:
                 <hash><cracked_delimiter><password>."""
            ),
            Argument('--match-string','-ms',
                help="""A string to match against any part of a line in
                the hash file. Useful for when identifying password reuse.
                """
            )
        ]
    )
]

class CrackedHash:

    def __init__(self,value,password,delimiter):

        self.value = value
        self.password = password
        self.escaped = re.escape(value)
        self.delimiter = delimiter
        self._matches = []

    def __eq__(self,value,reg=False):

        if not reg:
            if value == self.value:
                return True
            else:
                return False
        else:
            if re.search(self.escaped,value):
                return True
            else:
                return False

    @property
    def matches(self):
        return [self.translate_match(m) for m in self._matches]

    def append_match(self,match):
        if not match in self._matches: self._matches.append(match)

    def translate_match(self,match):
        return f'{match}{self.delimiter}{self.password}'

def parse_cracked(s,delimiter):
    
    if not s.find(delimiter):
        raise ValueError(f"""Delimiter value ({delimiter}) value not
        found in the cracked value ({delimiter}).""")

    split = s.split(delimiter)

    return CrackedHash(value=delimiter.join(split[0:split.__len__()-1]),
            password=split[-1],delimiter=delimiter)

def find_match(cracked,line):

    output = []
    for cracked_hash in cracked:
        if cracked_hash == line or cracked_hash.__eq__(line,True):
            output.append(cracked_hash.translate_match(line))

    return output


def monitor_results(ready_all=False):

    global results

    while True:

        ready = False
        for result in results:
            if result.ready():
                output = result.get()
                if output: print('\n'.join(output))
                del(results[results.index(result)])
                ready = True

        if ready and ready_all and not results:
            break
        elif ready and not ready_all:
            break
        else: sleep(.1)

#results = []

def parse(hash_files=None, cracked_delimiter=':', cracked_files=None,
        cracked_hashes=None, match_string=None, process_count=4,
        output_file=None, *args, **kwargs):


    if hash_files: helpers.validate_input_files(hash_files)
    if cracked_files: helpers.validate_input_files(cracked_files)

    if cracked_hashes:
        esprint(f'Loading cracked hashes: {",".join(cracked_hashes)}')
        cracked = [parse_cracked(cracked_hash,cracked_delimiter) for cracked_hash in
                cracked_hashes]

    elif cracked_files:
        esprint(f'Loading hashes from cracked files')
        for cracked_file in cracked_files:
            with open(cracked_file) as cfile:
                cracked = [parse_cracked(c.strip(),cracked_delimiter) for c in cfile
                        if c and c!='\n']

    elif match_string:
        esprint(f'Handling static string search')
        cracked = [CrackedHash(match_string,'STATIC_STRING_SEARCH')]

    # TODO: Implement multiprocessing
    # Currently having an issue with pickling the find_match function
    #pool = Pool(process_count)
    #global results

    if output_file: output_file = open(output_file,'w')

    try:

        for cracked_hash in cracked:

            for hash_file in hash_files:

                with open(hash_file) as hash_file:

                    for line in hash_file:
                        line = line.strip()

                        if cracked_hash == line or cracked_hash.__eq__(line,True):
                            s = cracked_hash.translate_match(line)
                            print(s)
                            if output_file: output_file.write(s+'\n')

    finally:

        if output_file: output_file.close()


# TODO: Additional multiprocessing code belo
# Finish!
#                if results.__len__() < process_count:
#                    results.append(pool.apply_async(find_match,(cracked,line,)))
#                else:
#                    monitor_results()
#
#
#    esprint('Waiting for all processes to finish execution')
#    if results: monitor_results(ready_all=True)
#    esprint('Done!')
#    pool.close()
#    pool.join()
