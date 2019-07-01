from parsuite.core.argument import Argument,DefaultArguments
from parsuite.abstractions.xml.generic import network_host as NH
from parsuite import helpers
from parsuite.core.suffix_printer import *
#import xml.etree.ElementTree as ET
from lxml import etree as ET
import argparse
import os
import csv
from sys import stdout

'''

Module will parse the HTML from the "People" section of a company
site on LinkedIn and dump information related to users.

Getting and Parsing the HTML:

    - Get a few contacts with the target company
    - Click the "people" link of the company profile
    - Scroll all the way to the bottom; JavaScript will load additional profiles
    - CTRL+Shift+I to access the developer console
    - Right-Click the HTML element and select "Copy Outer HTML"
    - Paste the HTML to a new file
    - Parse with this module

- Title element class attribute: artdeco-entity-lockup__title ember-view
- User URI Path HTML Class: link-without-visited-state ember-view
    - The path is stored in the href element attribute
- Name HTML Class: org-people-profile-card__profile-title t-black lt-line-clamp lt-line-clamp--single-line ember-view
    - Display name is stored as the text

'''

help='Parse the HTML content from the People section of a company ' \
    'profile and dump the path component and display name from each ' \
    'rendered user.'

args = [
    DefaultArguments.input_file,
    DefaultArguments.output_file_stdout_default,
    Argument('--delimiter','-d',
        default=':',
        help='''Field delimiter for CSV output. Set to ":" by default to avoid
         extra quoting when commas appear in display name values.
        '''
    )
]

def parse(input_file=None, output_file=None, delimiter=None, **kwargs):

    esprint(f'Parsing input file: {input_file}')

    # parse the input file as HTML
    tree = ET.parse(input_file,ET.HTMLParser())

    if output_file != stdout:
        outfile = open(output_file, 'w', newline='')
    else: outfile = output_file
    
    # Get the title elements
    esprint('Extracting paths and names')

    writer = csv.writer(outfile, delimiter=delimiter)
    writer.writerow(['name','path','subtitle'])

    for content in tree.xpath('//artdeco-entity-lockup-content'):

        title = content.xpath('./artdeco-entity-lockup-title')
        
        if title is None: continue

        title = title[0]
        
        a = title.find('a[@href]')

        if a is None: continue

        # Get the LinkedIn path
        path = a.get('href')

        # Get the display name
        name = a.getchildren()[0] \
                .text \
                .strip()

        # Get the subtitle
        sub = ''

        subtitle = content.xpath('./artdeco-entity-lockup-subtitle')

        if subtitle is not None:

            subs = []

            for span in subtitle[0].xpath('.//span'):

                if span.text and span.text != '...': sub += f'{sub} {span.text.strip()}'

        writer.writerow([name,path,sub.strip()])

    outfile.close()

    return 0
