from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
import json
import re
from pathlib import Path
from sys import exit
from neo4j import GraphDatabase
import pdb
import csv
from collections import namedtuple

help='Accept a CSV file and upate a series of BloodHound nodes in a ' \
'given Neo4j database.'

args = [
    DefaultArguments.input_files,
    Argument('--username',
        help='Neo4j username',
        required=True
    ),
    Argument('--password',
        help='Neo4j password',
        required=True
    ),
    Argument('--bolt-uri',
        help='URI to the Neo4j socket, e.g. bolt://localhost:7687',
        required=True
    )
]

# ===============
# CSV FILE FORMAT
# ===============
'''The input CSV file must have the following fields in the initial line to
serve as a header.

WARNING: THE VALUES FOR THESE FIELDS ARE CASE SENSITIVE!!!!
'''

CSV_FIELDS = [
    'node_type',            # The type of node to update. One of the following
                            # - Computer
                            # - Domain
                            # - GPO
                            # - Group
                            # - OU
                            # - User

    'query_property_name',  # The name of the node type that will be queried on,
                            # such as "name" for a user

    'query_property_value', # The value that must match the query_property_name
                            # value. Together, these form a query like:
                            # MATCH (u:User) u.name = 'JIM@MICROTURD.COM'

    'update_property_name', # The name of the property that will be updated on the
                            # matched node. For instance, 'owned' would be a common
                            # property to update on User nodes

    'update_property_value' # The update_property_name property on the matched node
                            # will be set to the value specified in this CSV field.
]

Record = None

class CSV:

    def __init__(self,infile):
        '''Initialize a faux CSV reader that returns a namedtuple
        upon __next__().
        '''

        # Get a CSV reader
        self.reader = csv.reader(infile)

        # Parse header
        self.header = [v.lower() for v in self.reader.__next__()]

        # Ensure header matches required fields
        for f in CSV_FIELDS:
            if not f in self.header:
                raise Exception(
                    f'Header in supplied CSV file {infile.name} is '
                    f'missing this field: {f}'
                )

        # Create the tuple structure from the header
        self.RECORD = namedtuple('Record', self.header)

    def __next__(self):
        '''Return a namedtuple representing the CSV record.
        '''
        return self.RECORD(*self.reader.__next__())

    def __iter__(self):
        return self

def withDriver(method):
    '''Decorator to interact with the underlying session. Implemented
    in this fashion just in case we need to add additional methods to
    the Neo4j class.
    '''

    def wrapper(self, record, *args, **kwargs):

        with self.driver.session() as session:
            try:
                return session.write_transaction(
                    method, record, *args, **kwargs
                )
            except Exception as e:
                raise e

    return wrapper

class Neo4j:
    # Pretty much stolen from this
    # https://neo4j.com/developer/python/
    
    def __init__(self, uri, username, password):
        '''Initialize a driver and set it as an instance attribute.
        '''

        self.driver = GraphDatabase.driver(uri, auth=(username, password))

    def close(self):
        '''Close the driver.
        '''

        self.driver.close()

    @withDriver
    def updateNode(tx, record, *args, **kwargs):
        '''Update a node from a Record instance, as defined by the CSV
        class during initialization.
        '''

        qpv = record.query_property_value
        upv = record.update_property_value

        # =====================
        # HANDLE BOOLEAN VALUES
        # =====================

        if qpv == 'true': qpv = True
        if upv == 'true': upv = True

        if qpv == 'false': qpv = False
        if upv == 'false': upv = False

        # ============================================================
        # MAKE SURE STRING VALUES ARE ESCAPED BEFORE BEING PASSED BACK
        # ============================================================

        if isinstance(qpv,str): qpv = '"'+qpv+'"'
        if isinstance(upv,str): upv = '"'+upv+'"'

        # ========================
        # APPLY THE DESIRED CHANGE
        # ========================

        return tx.run(
            'MATCH (n:{node_type}) ' \
            'WHERE n.{query_property_name}={query_property_value} ' \
            'SET n.{update_property_name}={update_property_value} ' \
            'RETURN n.{update_property_name}'.format(
                node_type=record.node_type,
                query_property_name=record.query_property_name,
                query_property_value=qpv,
                update_property_name=record.update_property_name,
                update_property_value=upv
            ))


def parse(input_files=None, bolt_uri=None, username=None,
        password=None, *args, **kwargs):

    # =============================
    # CONNECT TO THE Neo4j DATABASE
    # =============================

    n = Neo4j(uri=bolt_uri, username=username, password=password)

    try:

        # =================
        # APPLY THE UPDATES
        # =================

        for infile in input_files:

            with open(infile) as infile:
        
                for record in CSV(infile):
                    
                    esprint(f'Updating: {record}')
                    n.updateNode(record)

    finally:

        # ==========================
        # CLOSE THE Neo4j CONNECTION
        # ==========================

        n.close()
    

    esprint('Finished!')
