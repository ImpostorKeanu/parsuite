from pathlib import Path
from parsuite.core.suffix_printer import *
from shutil import rmtree
from xml.etree.ElementTree import Element
from parsuite.abstractions.xml import validators
import types
from base64 import b64encode


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
        'Module Error: Module must have a help string variable.'
    )

    assert 'args' in attrs and type(module.args) == list, (
        'Module Error: Module must have a list of arguments.'
    )

    assert 'parse' in attrs and type(module.parse) == types.FunctionType, (
        'Module Error: Module must have a parse attribute'
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
