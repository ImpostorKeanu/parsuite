from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
import xml.etree.ElementTree as ET
import argparse
from sys import exit,stdout
from datetime import datetime
from base64 import b64encode
import json
import re
import pdb

help = '''Parse cookies from the results table of a Burp Intruder attack
and translate them to an Authmatrix state file for those users. Warning:
 This tool assumes that the username is in Payload1. Also make sure that
 invalid records are removed from the table file, otherwise they will
 be translated and added to the JSON file.
'''

args = [
    DefaultArguments.input_files,
    Argument('--delimiter','-d',
        default='\t',
        help='Delimiter that separates values. Default: \\t (tab character)'),
    Argument('--payload-number','-pn',
        default='1',
        help='''Payload number containing the username. You can get
        this value by looking at the output table and mapping the
        column header to the username values.
        '''),
    Argument('--user-role-map-file','-uf',
        help='''Map users back to a role. File should provide user to role
        mappings, where the first line should be a header with a "username"
        column and a "role" field. All intermediary characters between these
        fields will be used as the delimiter for all future records, e.g.:
        "username<:::>role" would result in the field
        seperator as being interpreted as "<:::>".
        '''),
    Argument('--pretty-print','-pp',
        action='store_true',
        help='Pretty print the results.'),
]

def encode(s):
    return b64encode(bytes(s,'utf8')).decode('utf8')

def parse(input_files=None, delimiter='\t', payload_number=1,
        pretty_print=None, user_role_map_file=None, **kwargs):

    if pretty_print: pretty_print=4
    else: pretty_print=None

    # json template    
    dct = {
            'version':'0.8',
            'arrayOfUsers': []
    }

    # =======================
    # MAP USERS BACK TO ROLES
    # =======================

    '''
    - counter - incremented after each new user/role combination 
    - roles - dictionary of role to users (list) mapping
    '''

    counter = 0 # used as index
    roles = {} # map of role to user lists
    role_index = {} # map of role name to role id
    array_of_roles = [] # array of role json options 

    if user_role_map_file:

        flag = True
        with open(user_role_map_file) as infile:
    
            for line in infile:
                line = line.strip()

                # ====================
                # PARSE THE MAP HEADER
                # ====================

                if flag:

                    try:
                        m = re.match('^(username|role)(.+?)(username|role)$',line,re.I)
                        groups = m.groups()

                        # ===============================
                        # DETERMINE OFFSETS AND DELIMITER
                        # ===============================

                        user_role_map_delimiter = groups[1]
                        role_offset = groups.index('role')
                        if role_offset == 2:
                            role_offset=1
                            username_offset=0
                        else:
                            role_offset=0
                            username_offset=1

                        flag = False
                        continue

                    except:

                        esprint(f'Invalid header line in user map: {line}\n\n' \
                                'This line should contain a header with two ' \
                                'field separated column names: role and ' \
                                'username. The sequence separating these values ' \
                                'will be used to split each record. For example: '\
                                '\n\n Header Line: role<:::>username\n\n' \
                                'Would result in the delimiter being "<:::>", ' \
                                ' to split all future records on')
                        exit()

    
                try:
    
                    # parse the user and the role
                    line = line.split(user_role_map_delimiter)
                    username,role = line[username_offset],line[role_offset]

    
                    # create a new role in the roles dict
                    if role not in roles:
                        roles[role] = [username]
                        role_index[role] = counter
    
                        # add the role to the array of roles
                        array_of_roles.append(
                            {
                                'index':counter,
                                'column':counter,
                                'name':role,
                                'deleted':False,
                                'singleUser':False,
                            }
                        )
    
                        counter += 1
    
                    # add the user to the currently existing role
                    else:
    
                        # Avoid duplicate users for a role
                        if username not in roles[role]:
                            roles[role].append(username)
    
    
                except Exception as e:
                    print(e)
                    esprint(f'Invalid role map line: {line}')

    # add the array of roles to the json object
    if roles: dct['arrayOfRoles'] = array_of_roles

    # ========================
    # BEGIN PARSING BURP FILES
    # ========================

    counter = 0

    for input_file in input_files:

        # =======================
        # PREPARE INPUT FROM FILE
        # =======================

        # Parse each record while splitting on the delimiter and
        # stripping newlines
        with open(input_file) as infile:
            records=[r.strip().split(delimiter) for r in infile]

        headers,records = records[0],records[1:]

        # ====================================
        # PARSE EACH RECORD INTO A USER OBJECT
        #=====================================
        
        payload_header = f'Payload{payload_number}'
        offset = 0
        username_offset,cookie_offset = 0,0

        # Determine the offset to each target value
        # - username_offset indicates where the username value is
        # - cookie_offset indicates where the cookie value is
        for header in headers:
            if header == payload_header:
                username_offset = offset
            elif header == 'Cookies':
                cookie_offset = offset
            
            if username_offset and cookie_offset: break
            offset += 1

        # =================
        # PARSE THE RECORDS
        # =================

        for record in records:

            try:
                username = record[username_offset]
                cookies = encode(record[cookie_offset])
            except:
                esprint(f'Invalid record: {record}')
                continue

            uroles = {}

            for role,users in roles.items():

                if username in users: is_member = True
                else: is_member = False
                    
                uroles[str(role_index[role])] = is_member

            dct['arrayOfUsers'].append(
                    {
                        'name':username,
                        'index':counter,
                        'tableRow':counter,
                        'cookiesBase64':cookies,
                        'headersBase64':[],
                        'roles':uroles
                    }
            )
            counter += 1

    # dump the state to stdout
    print(json.dumps(dct,indent=pretty_print))

    return 0
