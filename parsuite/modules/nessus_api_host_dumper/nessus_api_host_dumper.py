from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
from sys import exit,stderr,stdout
import re
from sys import exit
import ipaddress
from nessrest import ness6rest
from pprint import pprint
from os import chdir
from pathlib import Path
from getpass import getpass
from termcolor import colored

help='''Extract affected hosts from the Nessus REST API. Useful in
situations when running a large scan or you don't want to deal with
exporting the .nessus file for use with the `xml_dumper` module.
'''

args = [
    Argument('--url','-u',
        default='',
        help='URL of Nessus server'),
    Argument('--username','-un',
        default='',
        help='Username for authentication'),
    Argument('--password','-p',
        default='',
        help='Password for authentication'),
    Argument('--severities','-svs',
        nargs='+',
        default=['low','medium','critical','high','info'],
        choices=['low','medium','critical','high','info'],
        help='Severeties to dump'),
    Argument('--scan-names','-sns',
        default=[],
        nargs='+',
        help='Scans to target. Will produce comprehensive list of affected hosts'),
    Argument('--list-scans','-l',
        action='store_true',
        help='List scans'),
    Argument('--insecure','-i',
        action='store_true',
        help='Validate the Nessus SSL certificate. Default: True'),
    Argument('--output-directory','-od',
        required=True,
        help='Directory where output should be written'),
]

COLORS = {'info':'blue','low':'green','medium':'yellow','high':'red',
        'critical':'magenta'}

class Severity:

    SEVS = SEVERITIES = {0:'info',1:'low',2:'medium',3:'high',
            4:'critical'}

    def __init__(self,weight,severity):

        assert weight.__class__ == int,'Weight must be an integer'
        assert severity.__class__ == str,'Severity must be a string'

        self.weight = weight
        self.severity = severity

    def __eq__(self,v):

        if v == self.weight or v == self.severity: return True
        else: return False

    def __str__(self):

        return self.severity

    @staticmethod
    def lookup(sev):

        if sev.__class__ == int and sev in Severity.SEVS:
            return Severity.SEVS[sev]
        elif sev.__class__ == str and sev in Severity.SEVS.values():
            for k,v in Severity.SEVS.items():
                if v == sev: return k
        else:
            raise Exception(
                    'Invalid severity value provided for lookup'
                )

class Scanner(ness6rest.Scanner):
    
    def scan_names(self):

        return [s['name'] for s in self.scan_list()['scans']]

    def plugin_output_to_hosts(self,plugin_id):

        self.action(action=f'scans/{self.scan_id}/plugins/{plugin_id}',
                method='GET')

        hostnames,sockets,network_sockets,app_sockets = [],[],[],[]

        # ================================
        # NORMALIZE THE VULNERABILITY NAME
        # ================================

        ai = additional_information = ''
        pd = plugin_description = self.res['info']['plugindescription']

        plugin_name = plugin_description['pluginname']
        ai += f'# Plugin Name: {plugin_name}\n'
        ai += '# Plugin ID: ' + \
                plugin_description['pluginattributes'] \
                ['plugin_information']['plugin_id'].__str__()+'\n'
        ai += '# Severity: ' + \
                Severity.lookup(plugin_description['severity']).upper()+'\n'
        ai += '# Description:\n\n' + \
                plugin_description['pluginattributes']['description'] + \
                '\n\n'

        plugin_name = re.sub('_{2,}','_',
                re.sub('\W','_',plugin_name)
            ).strip('_').lower()

        # ========================
        # PARSE EACH PORT INSTANCE
        # ========================

        for output in self.res['outputs']:

            for header,results in output['ports'].items():

                port,network_proto,app_proto = header.split(' / ')
                for host in results:
                    hostname = host['hostname']
                    hostnames.append(hostname)

                    if port != '0':

                        socket = f'{hostname}:{port}'
                        sockets.append(socket)

                        if network_proto:
                            network_sockets.append(f'{network_proto}://{socket}')
    
                        if app_proto:
                            app_sockets.append(f'{app_proto}://{socket}')

        return {'plugin_name':plugin_name,
                'severity':Severity.lookup(output['severity']),
                'hostnames':hostnames,'sockets':sockets,
                'network_sockets':network_sockets,
                'app_sockets':app_sockets,'plugin_id':plugin_id,
                'additional_information':ai}


SEVS = SEVERITIES = [Severity(k,v) for k,v in 
        {0:'info',1:'low',2:'medium',3:'high',4:'critical'}.items()]
            
def write_lines(filename,lines):
    with open(filename,'a+') as outfile:
        for line in lines:
            outfile.write(line+'\n')

def parse(url=None,username=None,password=None,severities=None,
        list_scans=False,scan_names=[],insecure=False,
        output_directory='', *args, **kwargs):
    

    # ============================
    # GET URL & Nessus Credentials
    # ============================

    if not url:
        url = input('Nessus URL: ')

    esprint('Getting user credentials...')
    print('\n\n',end='')
    if not username:
        username = input('Nessus Username: ')

    if not password:
        password = getpass('Password: ')
    print('\n\n')
    
    # =====================
    # AUTHENTICATE THE USER
    # =====================

    scanner = Scanner(url=url,login=username,password=password,
            insecure=insecure)
    
    # =====================
    # LIST SCANS IF DESIRED
    # =====================

    if list_scans:
        esprint('Listing scans by name:\n')
        for s in scanner.scan_names():
            print('- '+s)

        return 0

    # ========================
    # PREPARE OUTPUT DIRECTORY
    # ========================

    root = Path(output_directory)
    if root.exists():
        raise Exception('Output directory already exists')

    root.mkdir()
    root = str(Path.cwd())+'/'+str(root)
    chdir(root)

    severities = [s for s in SEVS if s in severities]

    # ======================
    # START EXTRACTING HOSTS
    # ======================

    esprint(f'Attempting to dump hosts from {", ".join(scan_names)}')

    report = {}

    snames = scanner.scan_names()

    for scan_name in scan_names:

        if scan_name not in snames:
            esprint(f'Unknown scan name: {scan_name}')
            continue
        else:
            esprint(f'Processing: {scan_name}')

        # ================
        # GET SCAN DETAILS
        # ================

        scanner.scan_details(scan_name)
        host_ids = []
        targets = scanner.res['info']['targets'].split(',')

        # ================================================
        # KEEP HOSTS ONLY IF THEY HAVE VULNS OF A SEVERITY
        # ================================================

        esprint(f'\tProcessing scan hosts')
        for host in scanner.res['hosts']:

            for sev in severities:
                if host[sev.severity]:
                    host_ids.append(host['host_id'])
                    break

        # ======================================
        # GET A LIST OF PLUGIN IDS FROM HOST IDS
        # ======================================
        
        esprint('\tProcessing scan plugins (this may take some time)')
        plugin_ids = []
        for host_id in host_ids:
            
            scanner.get_host_details(scanner.scan_id,host_id)

            host = scanner.res
            for vuln in host['vulnerabilities']:

                if not vuln['severity'] in severities:
                    continue

                if vuln['plugin_id'] not in plugin_ids:
                    plugin_ids.append(vuln['plugin_id'])

        # ============================
        # GET AFFECTED HOSTS BY PLUGIN
        # ============================

        esprint('\tProcessing target plugin ids')
        for id in plugin_ids:
            output = scanner.plugin_output_to_hosts(id)

            cp = Path(output['severity'])


            if not cp.exists(): cp.mkdir()
            chdir(cp)

            cp = Path(output['plugin_name'])
            if not cp.exists():
                cp.mkdir()
                new = True
            else:
                new = False
            chdir(cp)
            
            col = colored(output['severity'].upper(),
                COLORS[output['severity']])

            esprint(f'\t\t[{col}] {output["plugin_name"][:50]}')

            if output['additional_information'] and new:
                write_lines('additional_information',
                        [output['additional_information']])

            if output['hostnames']:
                write_lines('hostnames',output['hostnames'])

            if output['sockets']:
                write_lines('sockets',output['sockets'])

            if output['network_sockets']:
                write_lines('network_sockets',output['network_sockets'])

            if output['app_sockets']:
                write_lines('app_sockets',output['app_sockets'])

            chdir(root)

        if targets:
            write_lines('targets.txt',targets)

    return 0






