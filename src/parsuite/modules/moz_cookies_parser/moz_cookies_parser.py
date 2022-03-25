from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
import xml.etree.ElementTree as ET
import argparse
import os
import sqlite3
import csv
from sys import exit,stdout
from datetime import datetime
import pdb

help = 'Accept an Firefox cookie file (SQLite3) and dump each record' \
        ' in CSV format. strLastAccessed and strCreationTime are added' \
        ' to each record to help find the freshest cookies. The final' \
        ' column contains the constructed cookie.'
    
FIELDS = ['id','baseDomain','name','value','host','path','expiry',
        'lastAccessed','creationTime','strExpiry','strLastAccessed',
        'strCreationTime','cookie']

args = [
    DefaultArguments.input_files,
    Argument('--delimiter','-d',
        default=',',
        help='Delimiter that separates values'),
    Argument('--fields','-fs',
        default=FIELDS,
        help='Which fields to return. Valid Values: %(default)s',
        nargs='+')
]

# https://linuxfreelancer.com/decoding-firefox-cookies-sqlite-cookies-viewer
MAXDATE=2049840000
def convert(epoch):
    mydate=epoch[:10]
    if int(mydate)>MAXDATE: mydate=str(MAXDATE)
    if len(epoch)>10: mytime=epoch[11:]
    else: mytime='0'
    fulldate=float(mydate+'.'+mytime)
    x=datetime.fromtimestamp(fulldate)
    return x.ctime()

def parse(input_files=None, delimiter=',', fields=None, **kwargs):

    input_files = input_files or []

    for f in fields:
        if f not in FIELDS: raise Exception(f'Invalid field value: {f}')

    cw = csv.writer(stdout,delimiter=delimiter)
    cw.writerow(fields)

    for input_file in input_files:

        esprint(f'Connecting to the database: {input_file}')
        try:
            conn = sqlite3.connect(input_file)
            cur = conn.cursor()

            # Get table columns
            cols = [r[1] for r in
                    cur.execute('PRAGMA table_info(moz_cookies)') \
                            .fetchall()]

            # Determine offsets within row for current table
            offsets = {f:cols.index(f) for f in cols}

            # Dump row contents
            for record in cur.execute('SELECT * FROM moz_cookies'):
                record = list(record)
                drecord = {f:record[o] for f,o in offsets.items()}

                if 'expiry' in cols:
                    drecord['strExpiry'] = convert(
                            str(record[offsets['expiry']])
                    )

                if 'lastAccessed' in cols:
                    drecord['strLastAccessed'] =  convert(
                            str(record[offsets['lastAccessed']])
                    )

                if 'creationTime' in cols:
                    drecord['strCreationTime'] =  convert(
                            str(record[offsets['creationTime']])
                    )

                if 'name' in cols and 'value' in cols:
                    drecord['cookie'] = f'{drecord["name"]}={drecord["value"]};'

                cw.writerow([drecord[f] for f in fields])

        except sqlite3.Error as e:
            esprint(f'Error occurred when dumping {input_file}!\n\n', WAR)
            print(e.__str__(),file=stderr)
            continue        

    return 0
