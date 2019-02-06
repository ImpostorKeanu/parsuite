from parsuite.core.argument import Argument
from parsuite import helpers
from parsuite.core.suffix_printer import *
from collections import OrderedDict 
import xml.etree.ElementTree as ET
import argparse
import os
import sqlite3
import re
from sys import exit

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

        format = re.sub(r'\[([0-9]+)?:?|([0-9]+)?\]','',format)
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

        # establish spans for delimiter values and add it to each span
         # results in a list like:
         # [
         #   start_match_span,
         #   end_match_span,
         #   (
         #       start_delimiter_span,
         #       end_delimiter_span
         #   )
         # ]

        keys = list(ordered.keys())
        for key in keys:

            # skip the final key
            if key == keys[-1]:
                ordered[key].append([])
                break

            # set start of delimeter to first character after field name
            start = ordered[key][1]
            ordered[key][1] -= 1
            stop = ordered[
                keys[
                    keys.index(key)+1]
                ][0]
            ordered[key].append([start,stop])

        ###

        # formatting and returning the final output string.
        output = ''
        for attr,spans in ordered.items():

            output += slices[attr]
            if not spans[-1]:
                continue

            start, stop = spans[-1]
            if start == stop:
                output += format[start]
            else:
                output += format[start:stop]

        return output               


help='Parse an SQLite3 database generated by recon-ng and dump the contacts out in '\
    'simple string format'

args = [
    Argument('--output-file','-of',required=True,
        help='Output file.'),
    Argument('--just-dump','-jd',action='store_true'),
    Argument('--renegade','-r',action='store_true'),
    Argument('--template', '-t',required=False,
        default='first_name[:] middle_name[:] last_name[:]',
        help='Help content here'),
    Argument('--lowercase', '-l', action='store_true'),
    Argument('--suffix','-s',required=False,
        help='A string to suffix to each formatted contact')
]

def parse(input_file=None, output_file=None, **kwargs):

    sprint(f'Connecting to the database: {input_file}')
    try:
        conn = sqlite3.connect(input_file)
    except sqlite3.Error as e:
        sprint('Error occurred!\n\n', WAR)
        print(e)
        sprint('Exiting module!')
        return 1

    sprint('Parsing names out of the contacts')
    cursor = conn.execute('SELECT * from CONTACTS;')

    with open(output_file,'w') as outfile:
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

                    sprint(f'Invalid Contact: {contact}',WAR)
                    print(e)

    sprint('Parsing complete!')

    return 0
