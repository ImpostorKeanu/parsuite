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

help='Expand a series of IPv4/6 ranges into addresses.'


args = [
    Argument('--url','-u',
        required=True,
        help='URL of Nessus server'),
    Argument('--username','-un',
        default='',
        help='Username for authentication'),
    Argument('--password','-p',
        default='',
        help='Password for authentication'),
    Argument('--severities','-sv',
        nargs='+',
        default=['low','medium','critical','high'],
        choices=['low','medium','critical','high'],
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

        plugin_name = self.res['info']['plugindescription']['pluginname']
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
                'app_sockets':app_sockets,'plugin_id':plugin_id}


SEVS = SEVERITIES = [Severity(k,v) for k,v in 
        {0:'info',1:'low',2:'medium',3:'high',4:'critical'}.items()]

def parse(url=None,username=None,password=None,severities=None,
        list_scans=False,scan_names=[],insecure=False,
        output_directory='', *args, **kwargs):

    if not username:
        username = input('Nessus Username: ')

    if not password:
        password = getpass('Password: ')

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
            print(s+'\n')
        return 0
    else:
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
            
            esprint('\tProcessing scan plugins')
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

            def write_lines(filename,lines):
                with open(filename,'w') as outfile:
                    for line in lines:
                        outfile.write(line+'\n')

            esprint('\tProcessing target plugin ids')
            for id in plugin_ids:
                output = scanner.plugin_output_to_hosts(id)

                cp = Path(output['severity'])
                if not cp.exists(): cp.mkdir()
                chdir(cp)

                cp = Path(output['plugin_name'])
                if not cp.exists(): cp.mkdir()
                chdir(cp)

                esprint(f'\t\tWriting: <{output["severity"]}> {output["plugin_name"][:50]}')

                if output['hostnames']:
                    write_lines('hostnames',output['hostnames'])

                if output['sockets']:
                    write_lines('sockets',output['sockets'])

                if output['network_sockets']:
                    write_lines('network_sockets',output['network_sockets'])

                if output['app_sockets']:
                    write_lines('app_sockets',output['app_sockets'])

                chdir(root)

    return 0






