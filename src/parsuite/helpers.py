from pathlib import Path
from parsuite.core.suffix_printer import *
from shutil import rmtree
from xml.etree.ElementTree import Element
from parsuite.abstractions.xml import validators
import types
from base64 import b64encode
from string import ascii_letters as ASCII
from random import randint
from slugify import slugify as slugify
from functools import wraps
import re
from copy import copy

DISALLOWED_PATTERN = '[^-a-zA-Z0-9\.]+'
SLUGIFY_DEFAULTS = dict(
    entities=True, decimal=True, hexadecimal=True,
    separator=' ', allow_unicode=True, max_length=255,
    save_order=True, lowercase=False,
    regex_pattern=DISALLOWED_PATTERN)

SLUGIFY_DEFAULTS_TAG = copy(SLUGIFY_DEFAULTS)
SLUGIFY_DEFAULTS_TAG['separator'] = '_'
del(SLUGIFY_DEFAULTS_TAG['regex_pattern'])

def slugified(slugify_kwargs:dict=SLUGIFY_DEFAULTS):
    '''Decorator that will automatically slugify string
    outputs. Useful in situations where the target value
    will be used as names for files and folders on a
    file system.
    '''

    def decorator(m):

        @wraps(m)
        def wrapper(self):

            text = m(self)
            if text is None:
                return None

            return slugify(text=str(text), **slugify_kwargs)

        return wrapper

    return decorator

class AttrDict:

    @property
    def __dict__(self):

        if not hasattr(self, 'DICT_ATTRS'):

            raise Exception(
                'AttrDict instances must have a DICT_ATTRS property '
                'that is a list of properties to include.')

        return {
            attr:getattr(self, attr)
            for attr in self.DICT_ATTRS if hasattr(self, attr)
        }

def gen_rand(length,used_values=None):

    used_values = used_values or []

    output = ''

    while True:
        for n in range(0,length):
            if randint(0,1): output += str(randint(0,9))
            else: output += ASCII[randint(0,ASCII.__len__()-1)]

        if not used_values or (used_values and not output in used_values):
            return output


def fingerprint_xml(tree):
    '''Query an etree object to determine the file format. Will return
    the name of the program that generated the file. Currently
    supported:

    - nmap
    - nessus
    - masscan
    '''

    fingerprint = None

    # Things are goofy here because I was too lazy to start
    # developing with lxml until later on. Now we have to compensate
    # for the type of queries that can be performed.

    if validators.validate_lxml_tree(tree):
        ele = tree.xpath('@scanner')
    else:
        ele = tree.find('[@scanner]')

    if hasattr(ele,'attrib'):
        fingerprint = ele.attrib['scanner']
    elif ele != None and ele != []:
        fingerprint = ele[0]

    if not fingerprint in ['masscan','nmap'] and (
            tree.findall('.//policyName').__class__
        ):

        fingerprint =  'nessus'

    return fingerprint

def base64(s):
    """Return a base64 encoded version of the supplied string."""

    return str(b64encode(bytes(s,'utf-8')),'utf-8')

def len_split(s,max_len=75):

    lines = []
    line = ''
    counter = 1
    for char in s:
        if counter < max_len:
            counter += 1
            line += char
        elif counter == max_len:
            counter = 1
            lines.append(line+char)
            line = ''

    if line: lines.append(line)

    return lines

def validate_module(module):

    attrs = module.__dir__()

    assert 'help' in attrs and type(module.help) == str, (
        f'Module Error: Module must have a help string variable. ({module})'
    )

    assert 'args' in attrs and type(module.args) == list, (
        f'Module Error: Module must have a list of arguments. ({module})'
    )

    assert 'parse' in attrs and type(module.parse) == types.FunctionType, (
        f'Module Error: Module must have a parse attribute. ({module})'
    )

def handle_output_directory(output_directory):

    # testing output directory
    op = output_path = Path(output_directory)
    
    # convenience references
    bo = base_output = str(op.absolute())
    
    if op.exists():

        i = ''
        while (i != 'destroy' and i != 'no'):
            sprint('Output directory already exists!\n')
            i = input('Destroy and rebuild output? (destroy/no): ')

        print()

        if i == 'destroy':

            sprint(f'Checking {bo}/.tripfile before destroying...')

            if Path(bo+'/.tripfile').exists():
                sprint('Destroying directory',WAR)
                rmtree(bo)

            else:
                sprint(f'Path is an invalid output directory: {bo}',
                    WAR)
                sprint('Exiting',WAR)
                exit()

        else:

            sprint('Exiting', WAR)
            exit()

    # create the output directory
    op.mkdir(parents=True)
    sprint(f'Creating new output directory: {bo}')
    
    # create the .tripfile
    Path(bo+'/.tripfile').touch()

    return bo

def validate_input_file(input_file):
    'Lazy sauce'

    assert Path(input_file).exists(), (
        'Input file does not exist.'
    )

def validate_input_files(input_files):

    for f in input_files:
        validate_input_file(f)
