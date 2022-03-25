from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
from collections import OrderedDict 
import xml.etree.ElementTree as ET
import argparse
import os
import sqlite3
import re
from sys import exit,stdout

class Contact:
    'Recon-ng contact record.'

    # TODO: Futureproof this by coding it such that it extracts the table schema
    attrs = ['first_name','middle_name','last_name',
            'email','title','region','country','module']

    # Regex to format the output
    format_regex = freg = re.compile(
        f'({"|".join(attrs)})(\[([0-9]+)?(:)?([0-9])?\])?'
    )

    def __str__(self,fields=attrs[:3],delimiter=' '):
        '''
        Return a space delimited string for the contact in the form of 
        ```first_name middle_name last_name```, where the spaces can be replaced
        with the value supplied to the ```delimiter``` parameter.
        '''

        return delimiter.join(
            [
                self.__getattribute__(f) for f in fields
                if f in Contact.attrs and self.__dict__[f]
            ]
        )

    def __init__(self, fields, renegade=True):
        '''
        Initialize a contact record. The ```renegade``` parameter dictates if
        a second contact should be parsed and bound to the returned object.
        '''

        # set all fields for the contact
        for a in Contact.attrs:
            ind = Contact.attrs.index(a)
            self.__setattr__(a,fields[ind])

        # create a renegade parsed contact
        if renegade:

            renegade = (re.sub(r'–\s.+','-',self.__str__())
                            .split('-')[0]
                            .strip()
                            .split(' '))

            # assume that any renegade with exactly two elements are
            # [first_name, last_name]
            if len(renegade) == 2:
                renegade.insert(1,None)

            # balance field count with that expected by contact object
            while len(renegade) < len(Contact.attrs):
                renegade.append(None)

            # create a new renegade contact and bind it to the contact
            self.renegade = Contact(
                renegade,
                False
            )

    def slice(self,template,pattern=freg,lower=False):
        '''
        Slice the contact according to a template. The template should be a
        simple string populated with attribute names, which can receive slice
        directives similar to that of how Python can slice arrays and strings.
        Returns a dictionary for each specified field and its relative slice.
        
        Example: ```first_name[1:3].middle_name[:2].last_name```

        - first_name: slices the first three characters, skipping char 0
        - middle_name: slices the first two characters
        - last_name: complete last name

        So, if the contact looks like:

        ```
        {
            first_name:  'Justin',
            middle_name: 'Fake',
            last_name:   'Angel'
        }

        ```

        The output would look like:

        ```
        {
            first_name:  'Ju',
            middle_name: 'Fa',
            last_name:   'Angel'
        }
        ```

        '''
        
        '''

        re.findall will return a list of tuples for each attribute match in the
            following form:

        In [88]: re.findall(pat,'first_name[1:3].middle_name[:2].last_name')
        Out[88]: 
            [
                ('first_name', '[1:3]', '1', ':', '3'),
                ('middle_name', '[:2]', '', ':', '2'),
                ('last_name', '', '', '', '')
            ]

        '''

        tuples = re.findall(pattern, template)
        if not tuples:
            raise Exception(
                'NoAttributesMatched'
            )

        output = {}
        for match in tuples:
            attr, slce, start, colon, stop = match

            nattr = self.__dict__[attr]

            if not nattr:
                raise Exception(
                    'AttributeIsNone'
                )
            elif lower:
                nattr = nattr.lower()

            if stop:
                stop = int(stop)

            if start or start == '0':
                start = int(start)

            if start and stop or (start == 0 and stop):
                output[attr] = nattr[start:stop]

            elif start and colon or (start == 0 and colon):
                output[attr] = nattr[start:]

            elif stop and colon:
                output[attr] = nattr[:stop]

            elif start or start == 0:
                output[attr] = nattr[start]

            else:
                output[attr] = nattr[:]

        return output

    def format(self, slices, format):
        '''
        Take a dictionary of slices (see ```Contact.slice```) and a template and
        format the contact according to the template.
        '''

        # scrub slice indicators
        format = re.sub(r'\[([0-9]+)?:?|([0-9]+)?\]','',format)

        # extract all attribute handles
        indices = re.findall(f'({"|".join(Contact.attrs)})',format)

        # split out on the attributes
        trailers = re.split(f'{"|".join(Contact.attrs)}',format)

        # remove leading/trailing trailers
        del(trailers[0])
        del(trailers[-1])

        trailers = dict(
            zip(indices,trailers)
        )
        
        spans = {}
        starts = []

        for attr in slices.keys():

            match = re.search(attr,format)

            if match:

                span = list(match.span())
                spans[attr] = span
                starts.append(span[0])


        # remapping the dictionary to match ordering of template
        starts = sorted(starts)
        ordered = OrderedDict()

        for start in starts:

            for attr,span in spans.items():
                if start == span[0]:
                    ordered[attr] = span
                    break

        # assembling final output
        output = ''
        for attr,spans in ordered.items():
            output += slices[attr]
            if attr in trailers:
                output += trailers[attr]

        return output               


help='Parse an SQLite3 database generated by recon-ng and dump the contacts out in '\
    'simple string format'

args = [
    DefaultArguments.input_file,
    Argument('--output-file','-of',
        default=stdout,
        help='Output file.'),
    Argument('--just-dump','-jd',action='store_true',
        help='''
        Dump each record to the output file in a string format. Each record will be
        in the following format:

        first_name middle_name last_name
        '''),
    Argument('--renegade','-r',action='store_true',
        help='''
        Do additional processing to avoid poorly formatted output. This has potential
        to mangle output and return incorrect addresses, though testing has resulted in
        overall accurate results.
        '''),
    Argument('--template', '-t',required=False,
        default='first_name[:] middle_name[:] last_name[:]',
        help='''
        Output template to apply to each record. Each field matches a column
        in the contacts table of the recon-ng database. Slices can be applied
        to the value for each field as well, e.g. first_name[0] would assure
        that only the first character of the first_name field is returned for
        each contact written to the output file.
        '''),
    Argument('--lowercase', '-l', action='store_true',
        help='Lowercase the record when returned in output.'),
    Argument('--suffix','-s',required=False,
        help='''
        A string to suffix to each formatted contact. Useful for adding a sequence
        for an email address, e.g. '@somedomain.edu'.
        ''')
]

def parse(input_file=None, output_file=None, **kwargs):

    esprint(f'Connecting to the database: {input_file}')
    try:
        conn = sqlite3.connect(input_file)
    except sqlite3.Error as e:
        esprint('Error occurred!\n\n', WAR)
        print(e)
        esprint('Exiting module!')
        return 1

    esprint('Parsing names out of the contacts')
    cursor = conn.execute('SELECT * from CONTACTS;')

    if output_file != stdout:
        outfile = open(output_file,'w')
    else:
        outfile = output_file

    try:

        if cursor:
    
            for contact in cursor:
    
                try:
                    c = Contact(contact)
    
                    # use the renegade contact if specified
                    if kwargs['renegade']:
                        c = c.renegade
    
                    # just dump a string of the contact to the output file
                    if kwargs['just_dump']:
                        outfile.write(
                            c.__str__() + '\n'
                        )
    
                    # reformat the contact and write it to disk
                    elif kwargs['template']:
    
                        slices = c.slice(
                            kwargs['template'],
                            lower=kwargs['lowercase']
                        )
    
                        # suffix if desired
                        if kwargs['suffix']:
    
                            outfile.write(
                                c.format(slices,kwargs['template'])+
                                f'{kwargs["suffix"]}\n'
                            )
    
                        else:
    
                            outfile.write(
                                c.format(slices,kwargs['template'])+'\n'
                            )
    
                except Exception as e:
    
                    esprint(f'Invalid Contact: {contact} ({e})',WAR)
                        #print('\t'+e.__str__())
    
        esprint('Parsing complete!')

    finally:

        outfile.close()

    return 0
