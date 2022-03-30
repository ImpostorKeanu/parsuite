import types
import re
from copy import copy
from pathlib import Path
from parsuite.core.suffix_printer import *
from shutil import rmtree
from xml.etree.ElementTree import Element
from parsuite.abstractions.xml import validators
from dataclasses import dataclass, field
from base64 import b64encode
from string import ascii_letters as ASCII
from random import randint
from slugify import slugify as slugify
from functools import wraps
import ipaddress
from urllib.parse import urlparse

IPv4 = ipaddress.IPv4Address
IPv6 = ipaddress.IPv6Address

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

@dataclass
class AddressOutputs:
    '''A class used to track various address values from
    parsed output files.
    '''

    ipv4_addresses:list = field(default_factory=list)
    ipv4_sockets:list = field(default_factory=list)
    ipv4_urls:list = field(default_factory=list)
    ipv4_transport_layer_sockets:list = field(default_factory=list)

    ipv6_addresses:list = field(default_factory=list)
    ipv6_sockets:list = field(default_factory=list)
    ipv6_urls:list = field(default_factory=list)
    ipv6_transport_layer_sockets:list = field(default_factory=list)

    hostnames:list = field(default_factory=list)
    hostname_sockets:list = field(default_factory=list)
    hostname_urls:list = field(default_factory=list)
    hostname_transport_layer_sockets:list = field(default_factory=list)

    def merge(self, src:'AddressOutputs', inline:bool=True):
        '''Merge the src AddressOutputs into self.

        Args:
            src: Source AddressOutputs object that will be merged
                into the current AddressOutputs object.
            inline: Indicates if src should be merged directly into
                self, or if a new AddressOutputs object should be
                returned.

        Returns:
            Merged AddressOutputs object.
        '''

        # Set the target
        target = self
        if not inline:
            target = AddressOutputs(**self.__dict__)

        # Merge the values
        for sk, sv in src.__dict__.items():
            tv = getattr(target, sk)
            tv += sv

        # Unique/sort the values
        for tk in target.__dict__.keys():
            setattr(
                target, tk,
                list(set(getattr(target, tk))))

        return target

class SortableURL:

    def __init__(self, scheme:str=None, address:str=None, port:int=None):

        self.scheme = scheme
        self.address = address
        self.port = port

    def __repr__(self):

        return "<{} scheme='{}' address='{}' port={} at {}>".format(
            str(self.__class__).split('.')[-1].strip("'>"),
            str(self.scheme),
            str(self.address),
            str(self.port),
            str(id(self)))

    @property
    def ip_obj(self):

        if not hasattr(self, '_ip_obj'):
            return None

        return self._ip_obj

    @ip_obj.setter
    def ip_obj(self, v:str):

        v = SortableURL.to_ip_obj(v)
        if SortableURL.is_ip_obj(v):
            self._ip_obj = v
        else:
            self._ip_obj = None

    @property
    def address(self):

        if not hasattr(self, '_address'):
            return None

        return self._address

    @address.setter
    def address(self, v:str):

        self._address = SortableURL.to_ip_obj(v)
        self.ip_obj = v

    def __lt__(self, v:str) -> bool:
        '''Perform a less than operation on the address property
        of the SortableURL object.

        Returns:
            Boolean object indicating if the address is less than v.

        Notes:
            - Attempts to convert v into an IPv4Address or IPv6Address
              will occur.
            - When conversion to an IP address objects fail, string
              values are compared.
        '''

        if self.ip_obj:

            if isinstance(v, SortableURL):
                v = v.ip_obj

            elif isinstance(v, str):
                v = SortableURL.to_ip_obj(v)

            if SortableURL.is_ip_obj(v) and SortableURL.is_ip_obj(v):
                return self.ip_obj < v

            # Compare a string value
            elif isinstance(v, str):
                return self.address == v

            return False

        else:

            if isinstance(v, str) and self.address:
                return self.address < v
            else:
                return False

    def __str__(self) -> str:
        '''Return the SortableURL object as an assembled string.

        Returns:
            Assembled URL string.
        '''

        scheme = self.scheme if self.scheme else ''
        
        if scheme.endswith('://'):
            out = self.scheme+str(self.address)
        elif scheme:
            out = self.scheme+'://'+str(self.address)

        return out + f':{self.port}' if self.port is not None else ''

    def value(self):
        '''Return the assembled URL value.
        '''

        return str(self)

    @staticmethod
    def is_ip_obj(v:object) -> bool:
        '''Determine if v is an IPv4 or IPv6 object.
        '''

        return isinstance(v, (IPv4, IPv6))

    @staticmethod
    def to_ip_obj(v):
        '''Convert v to an IPv4 or IPv6 object.
        '''

        if SortableURL.is_ip_obj(v):
            return v
        else:
            try:
                return ipaddress.ip_address(v)
            except ValueError:
                return v

class AttrDict:
    '''Reads property values from a DICT_ATTRS class property
    and produces a dictionary when the __dict__ property
    is referenced.
    '''

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
