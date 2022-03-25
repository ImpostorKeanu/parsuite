from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
import json
import re
from pathlib import Path
from sys import exit
import pdb


PROP_RE=re.compile('^(?P<property>.+?)\=(?P<value>.+)$')

help='Modify each BloodHound JSON file and add a property to' \
     'each object'

args = [
    Argument('--json-files','-jfiles',
        nargs='+',
        required=True,
        help='JSON files to parse/modify'
    ),
    Argument('--properties','-ps',
        nargs='+',
        required=True,
        help='Space delimited properties to alter in <property>=' \
             '<value> format, i.e. "owned=true"'
    ),
    Argument('--target-objects','-tos',
        nargs='+',
        required=False,
        help='Space delimited objects to receive the properties' \
             ' in the format of <match_proprety>=<match_value>.' \
             'match_property specifies the property key to matc' \
             'h and match_value specifies the value that should' \
             ' be associated with that property. You most likely ' \
             'want to match on the "name" property, e.g. name=ADM' \
             'IN@DOMAIN.COM'
    ),
    Argument('--target-objects-files','-tofs',
        nargs='+',
        required=False,
        help='Files containing target objects. See target-objects ' \
             'flag for more information on the expected format. Ea' \
             'ch value should be newline separated')
]

def check_file(pth):
    '''Determine if a file is on the local file system and exit
    if it isn't.
    '''

    if not Path(pth).exists():
        esprint(f'File not found: {pth}')
        exit()

def parse_property(value):
    '''Parse a property in the format of <name>=<value>. Exit
    the program should this format not be satisfied.
    '''

    match = re.match(PROP_RE,value)

    if not match:
        esprint(f'Failed to parse target object value: {value}. Exiting')
        exit()

    return match.groups()

def parse_target_object(value,dct):
    '''Parse a target object in the same format of a property
    and add it to the dictionary containing a list of values
    to match on.
    '''


    key,value = parse_property(value)
    if not key in dct: dct[key]=[value]
    else: dct[key].append(value)

def parse(json_files, properties, target_objects=None,
        target_objects_files=None, *args, **kwargs):

    # Prepare the arguments
    if not target_objects and not target_objects_files:
        esprint(f'target_objects or target_objects_files are required' \
                '. Exiting.')
        exit()

    target_objects = [] if target_objects == None \
            else target_objects
    target_objects_files = [] if target_objects_files == None \
            else target_objects_files

    # Verify presence of each file
    jsons = []
    for f in json_files:
        esprint(f'Attempting to import {f}')
        try:
            check_file(f)
            with open(f) as infile:
                jsons.append(json.loads(infile.read().encode('utf8')))
        except Exception as e:
            esprint(f'Failed to import JSON file: {f}. Exiting.')
            esprint(e)
            exit()


    # Validate format of each property
    props = {}
    for p in properties:
        esprint(f'Attempting to parse property: {p}')

        match = re.match(PROP_RE,p)

        if not match:
            esprint(f'Failed to parse property input: {p}. Exiting')
            exit()

        key,value=parse_property(p)
        props[key]=value

    # Validate the target objects
    target_objs = {}
    for to in target_objects:
        parse_target_object(to,target_objs)

    # Validate the target objects files
    for f in target_objects_files:
        check_file(f)
        with open(f) as infile:
            for line in infile:
                parse_target_object(line.strip(),target_objs)

    # TODO: Update each of the JSON files
    esprint('Updating JSON content...')
    for jind in range(0,jsons.__len__()):
        js = jsons[jind]
        key = list(js.keys())[0]

        # Iterate over each of the target objects
        for obj in js[key]:

            # Disregard any object that doesn' have a
            # "Properties" member
            if 'Properties' not in obj: continue

            # Scan for target objects
            for prop,targets in target_objs.items():

                # property key must be in target objects properties
                # and the value of that property must be in the
                # targets of target_objects
                if prop in obj['Properties'] and \
                        obj['Properties'][prop] in targets:

                    # Update the value
                    for iprop,value in props.items():
                        obj['Properties'][iprop]=value

    # TODO: Write the updated JSON files to disk
    esprint('Updating files...')
    for find in range(0,json_files.__len__()):
        fname = json_files[find]
        with open(fname,'w') as outfile:
            json.dump(jsons[find],outfile)

    esprint('Finished!')

























