from parsuite.core.argument import Argument,DefaultArguments,ArgumentGroup,MutuallyExclusiveArgumentGroup
from parsuite import helpers
from parsuite.core.suffix_printer import *
from sys import stderr,exit
from lxml import etree as ET
import re
import argparse

help='''Dump LDAP objects from a file exported by Wireshark in PDML format.
'''

args = [
    DefaultArguments.input_files,
]

def parse(input_files, *args, **kwargs):

    for infile in input_files:

        # ==================
        # PARSE THE XML FILE
        # ==================
    
        esprint(f'Parsing {infile}')
        tree = ET.parse(infile)

        # ========================================
        # ITERATE OVER EACH searchResEntry_element
        # ========================================

        for entry_element in tree.xpath('//field[@name="ldap.searchResEntry_element"]'):

            # =======================================
            # EXTRACT AND DUMP THE PRIMARY objectName
            # =======================================

            object_name = ' ' \
                    .join(
                        entry_element.find('./field[@name="ldap.objectName"]') \
                            .get('showname').split(' ')[1:]
                    )

            # ===========================================================
            # EXTRACT AND DUMP EACH ATTRIBUTE ASSOCIATED WITH THAT OBJECT
            # ===========================================================

            '''
            There's a metric-turd-ton of information in these attributes, much of which
            is unrelated to users. Some values appear to be SNMP community strings. This
            may merit additional research in the future.
            '''

            attribute_values = entry_element.xpath(
                './/field[@name="ldap.AttributeValue"]'
            )

            # Print the object name to stdout
            if object_name and attribute_values.__len__() > 0:
                print(f'\nLDAP Object Name: {object_name}\n')

            # Print each attribute to stdout
            for attribute_value in attribute_values:

                value = attribute_value.get('showname')

                # Restrict only to object with the domain component prefix
                if value.find('DC=') < 0: continue

                # Remove the following prefix from each attribute: "AttributeValue: "
                value = value.replace('AttributeValue: ','')
                print(value)

    return 0
