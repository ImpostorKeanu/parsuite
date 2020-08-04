from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
import argparse
import os
from re import findall

help = """Define an insertion point (signature) within a template file
and replace the line with a payload from a distinct file. Useful in
situations where an extremely long payload needs to be inserted, such
as when working with hex shellcode for stageless payloads.
"""

args = [
    Argument('--template-file','-tf',
        required=True,
        help="""Template file that will be read in. A signature
        string must be present at the beginning of a line, which
        is where the payload will be inserted."""),
    Argument('--payload-file','-pf',
        required=True,
        help="""File containing the payload to insert"""),
    Argument('--output-file','-of',
        required=True,
        help="""File to write the output to."""),
    Argument('--signature','-s',
        required=True,
        help="""Signature string. Must be at the beginning of a
        line on it's own. This value will be replayed with the
        payload""")
]

def parse(template_file=None, payload_file=None, signature=None,
        output_file=None, *args, **kwargs):

    esprint('Checking input files')
    helpers.validate_input_files([template_file, payload_file])

    esprint('Parsing the payload file')
    with open(payload_file) as infile: payload = infile.read()

    esprint('Opening and parsing the template file')
    inserted = False
    with open(template_file) as template:
        lines = []
        for line in template:
            if signature == line.strip():
                esprint('Inserting the payload.')
                line = payload
                inserted = True
            lines.append(line)

    if not inserted:
        esprint("""WARNING: Signature never detected! Payload was not
        inserted. Note that the signature must be on its own line with
        no other content.""")

    esprint('Writing the output file')
    with open(output_file,'w') as outfile:
        for line in lines:
            outfile.write(line)
