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
        ' to each record to help find the freshest cookies.'

args = [
    DefaultArguments.input_files,
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

def parse(input_files=None, **kwargs):

    input_files = input_files or []

    cw = csv.writer(stdout)
    cw.writerow('id baseDomain originAttributes name value host path ' \
            'lastAccessed creationTime isSecure isHTTPOnly ' \
            'inBrowserElement sameSite moz_uniqueid strLastAccessed ' \
            'strCreationTime'.split(' '))

    for input_file in input_files:

        esprint(f'Connecting to the database: {input_file}')
        try:
            conn = sqlite3.connect(input_file)
            cur = conn.cursor()
            for record in cur.execute('SELECT * FROM moz_cookies'):
                record = list(record)
                record += convert(str(record[8])),convert(str(record[9]))
                cw.writerow(record)
        except sqlite3.Error as e:
            esprint(f'Error occurred when dumping {input_file}!\n\n', WAR)
            print(e.__str__(),file=stderr)
            continue        

    return 0
