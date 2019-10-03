from parsuite.core.argument import (Argument,DefaultArguments,
        ArgumentGroup,MutuallyExclusiveArgumentGroup)
from parsuite import helpers
from parsuite.core.suffix_printer import *
from multiprocessing import Pool
import argparse
import os
import re
from time import sleep

help = '''Remove lines found in bad files from lines found in good
files and write the resultant set of good lines to an output file.
'''

args = [
    Argument('--bad-files','-bfs',
        required=True,
        nargs='+',
        help='Lines that will be removed from good files'
    ),
    Argument('--good-files','-gfs',
        required=True,
        nargs='+',
        help='Lines that will be matchedby bad lines and removed'
    ),
    Argument('--output-file','-of',
        required=False,
        help='File to write output.'
    ),
]

def parse(bad_files=None, good_files=None, output_file=None,
        *args, **kwargs):

    good_lines,bad_lines = [],[]

    # ===============
    # LOAD GOOD LINES
    # ===============

    for good_file in good_files:

        with open(good_file) as infile:

            for line in infile:
                if not line in good_lines: good_lines.append(line.strip())

    # ================================
    # DELETE BAD LINES FORM GOOD LINES
    # ================================

    for bad_file in bad_files:

        with open(bad_file) as infile:

            for line in infile:
                while True:
                    try:
                        good_lines.remove(line.strip())
                    except:
                        break


    # ========================
    # WRITE GOOD LINES TO DISK
    # ========================

    with open(output_file,'w') as outfile:

        for line in good_lines:
            outfile.write(line+'\n')

    return 0
