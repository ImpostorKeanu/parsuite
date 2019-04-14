from pathlib import Path
from parsuite.core.suffix_printer import *
from shutil import rmtree
import types

def fingerprint_xml(tree):
    '''Query an etree object to determine the file format. Will return
    the name of the program that generated the file. Currently
    supported:

    - nmap
    - nessus
    - masscan
    '''

    ele = tree.find('[@scanner]')

    fingerprint = None
    if ele:
        if ele.attrib['scanner'] == 'masscan':
            fingerprint =  'nmap'
        elif ele.attrib['scanner'] == 'nmap':
            fingerprint =  'nmap'
    elif tree.find('.//policyName').__class__ == ET.Element:
        fingerprint =  'nessus'

    return fingerprint


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
