from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
import re
import argparse
import os

# Initial Users List
  # index: 0x8d41 RID: 0x3189 acb: 0x00020015 Account: $9CC000-2LH Name: (null)    Desc: (null)
  # Element 7 will contain the user name
# user_signature0 = '^index: 0x.+Account: (?P<username>.+) Name: .+ Desc: .+'
user_signature0 = '^index: 0x.+Account:\s+(?P<username>.+).+Name:.+$'

# Second Users List
  # user:[readingadmin] rid:[0x1f4]
  # Split by spaces
  # capture all contents in [] of element 0 after split
user_signature1 = '^user:\[(?P<username>.+)\] '

# Group membership signature
  # Group 'Custom Group' (RID: 559) has member: domain\user
group_membership_signature = '^Group \'(?P<groupname>.+)\' .+has member: (?P<username>.+)$'

# Group signature:
  # group:[Network Configuration Operators] rid:[0x22c]
group_signature = '^group:\[(?P<groupname>.+)\] rid:\[(?P<>.+)\]'

# Builtin groups header:            'Getting builtin groups'
# builtin group memberships header: 'Getting builtin group memberships'
# Local groups header:              'Getting local groups'
# Local group memberships header:   'Getting local group memberships'
# Domain groups header:             'Getting domain groups'
# Domain group memberships header:  'Getting domain group memberships'

help=''

args = [
    DefaultArguments.input_file,
    Argument('--output-directory', '-od', required=True,
        help='Output directory.')
]

def parse(input_file=None, output_directory=None,
        tcpwrapped=None, **kwargs):

    bo = base_output_path = helpers.handle_output_directory(
        output_directory
    )

    users = []
    groups = {}

    ifile = None
    try:

        ifile = open(input_file)


        for line in ifile:

            line = line.strip()

    finally:

        if ifile: ifile.close()





    return 0
