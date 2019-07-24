from parsuite.core.argument import Argument,DefaultArguments
from parsuite.abstractions.xml.generic import network_host as NH
from parsuite import helpers
from parsuite.core.suffix_printer import *
#import xml.etree.ElementTree as ET
from lxml import etree as ET
import argparse
import os
import csv
from sys import stdout, exit
from base64 import b64decode

from http.server import BaseHTTPRequestHandler
from http.client import HTTPResponse
from io import BytesIO

from IPython import embed
import pdb

class HTTPRequest(BaseHTTPRequestHandler):
    '''Parse an HTTP request.
    '''

    def __init__(self, request_bytes):

        self.rfile = BytesIO(request_bytes)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()
        self.headers = dict(self.headers)

        self.body = self.rfile.read()
        self.sbody = self.body.decode('utf8')

        self.content = self.body
        self.scontent = self.sbody

        self.rfile.seek(0)

        self.firstline = self.requestline

    def send_error(self, code, message):

        self.error_code = code
        self.error_message = message

class HTTPResponse(HTTPResponse):
    '''Parse an HTTP response.
    '''

    def __init__(self, response_bytes):
        super().__init__(Socket(response_bytes))
        self.begin()

        self.firstline = f'{self.status} {self.reason} ' \
            f'{self.version}'

        self.headers = dict(self.headers)

        self.content = self.read()
        self.scontent = self.content.decode('utf8')

        self.body = self.content
        self.sbody = self.scontent

class Socket:
    '''Fake a socket since the HTTPResponse class
    will try to read from an io like object.
    '''

    def __init__(self, response_bytes):
        self._file = BytesIO(response_bytes)

    def makefile(self, *args, **kwargs):
        return self._file

class Host:
    '''host element from a Burp item element.
    '''

    def __init__(self,value,ip=None):

        self.value = value or None
        self.ip = ip

    def __repr__(self):

        return self.value

    def __eq__(self,v):

        if self.value == v: return True
        else: return False

    @staticmethod
    def from_lxml(lxml):
        return Host(lxml.text, lxml.get('ip'))

class ItemHTTPPart:

    PARSER_CLASS = None

    def __init__(self, raw, base64=False):

        self.raw = raw
        self.base64 = base64
        self.parser_class = None
        self.value = None

    def parse(self):

        assert self.__class__.PARSER_CLASS, (
            'No parser class set'
        )

        if self.base64: content = Base64.b64tob(self.raw)
        else: content = raw

        self.value = self.__class__.PARSER_CLASS(
            content
        )

    @classmethod
    def from_lxml(kls,lxml):
        return kls.PARSER_CLASS(Base64.b64tob(lxml.text))

class Request(ItemHTTPPart):
    PARSER_CLASS = HTTPRequest

class Response(ItemHTTPPart):
    PARSER_CLASS = HTTPResponse

class Item:
    
    ATTRS = [
                'time', 'url', 'host', 'port', 'protocol', 'method', 'path',
                'extension', 'request', 'response', 'status', 'responselength',
                'mimetype', 'comment'
            ]

    def __init__(self, time, url, host, port, protocol, method, path,
            extension, request, response, status, response_length, mimetype,
            comment, *args, **kwargs):

        # Initialize instance variables
        self.response_length = response_length
        for a in Item.ATTRS:
            if a == 'responselength': continue
            self.__setattr__(a,locals()[a])

    @staticmethod
    def from_lxml(lxml):
        '''Create an Item object from an lxml element.
        '''

        '''Logic below will automatically extract all text content
        for basic XML elements. Complex ones requiring additional
        processing are handled individually.
        '''
        
        # ===========================
        # PARSE OUT EACH TEXT ELEMENT
        # ===========================

        kwargs = {}

        blacklist = ['request','response','host']
        for child in lxml.getchildren():
            if child.tag in blacklist: continue
            kwargs[child.tag] = child.text

        # ==========================
        # PARSE COMPLEX XML ELEMENTS
        # ==========================

        kwargs['host'] = Host.from_lxml(lxml.find('host'))
        kwargs['request'] = Request.from_lxml(lxml.find('request'))
        kwargs['response'] = Response.from_lxml(lxml.find('response'))
        kwargs['response_length'] = kwargs['responselength']

        return Item(**kwargs)

class Base64:
    '''Simplify base64 decoding.
    '''

    @staticmethod
    def b64decode(encoded):
        '''Decode a string and return bytes.
        '''

        return b64decode(bytes(encoded,'utf8'))

    @staticmethod
    def b64tos(encoded):
        '''Decode a string and return a string.
        '''

        return Item.b64decode(encoded).decode('utf8')

    # Alias b64decode
    b64tob = b64decode

# TODO: Update this
help = '''Accept an XML file containing Burp items and
extract the request/response to a file.'''

args = [
    DefaultArguments.input_file,
    Argument('--output-directory', '-od', required=True,
        help='Output directory.'),
]

def parse(input_file=None, output_directory=None, **kwargs):

    esprint(f'Parsing input file: {input_file}')
    

    # parse the input file as HTML
    tree = ET.parse(input_file)
    
    bo = base_output_path = helpers.handle_output_directory(
        output_directory
    )
    os.chdir(bo)

    counter = 0

    for item in tree.xpath('//item'):

        try:

            item = Item.from_lxml(item)

        except Exception as e:

            esprint(f'Failed to parse item #{counter}: {e}')
            continue

        with open(str(counter)+'.req','w') as outfile:

            outfile.write(
                f'URL: {item.url}\r\n{item.request.firstline}\r\n'
            )

            for k,v in item.request.headers.items():
                outfile.write(
                    f'{k}: {v}\r\n'
                )

            outfile.write('\r\n\r\n')
            outfile.write(item.request.sbody)
        
        if item.mimetype: mimetype = item.mimetype.lower()
        else: mimetype = 'no_mimetype'

        with open(str(counter)+'.resp.'+mimetype,'w') as outfile:
            
            outfile.write(
                f'URL: {item.url}\r\n{item.response.firstline}\r\n'
            )

            for k,v in item.response.headers.items():
                outfile.write(
                    f'{k} {v}\r\n'
                )

            outfile.write('\r\n\r\n')
            outfile.write(item.response.sbody)
        
        counter += 1

    return 0
