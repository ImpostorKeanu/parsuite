from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
from pathlib import Path
import xml.etree.ElementTree as ET
import argparse
import os
import re

help='Parse a Nessus file and dump the contents to disk by: '\
    'risk_factor > plugin_name'

args = [
    DefaultArguments.input_file,
    Argument('--output-directory', '-od', required=True,
        help='Output directory.')
]

# plugin_name_re = pname_re = re.compile('(\-|\s|\\|\<|\>|\=|\(|\)|/|\'|\"|\.)+')
plugin_name_re = pname_re = re.compile('(\s|\W)+')
ipv4_re = i4_re = re.compile('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
ipv6_re = i6_re = re.compile('^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$')
fqdn_re = re.compile('[a-zA-Z]')

def check_ip(name):

    if re.match(i4_re,name):
        return 'ipv4'
    elif re.match(i6_re,name):
        return 'ipv6'
    else:
        return 'fqdn'

class Port:

    def __init__(self, number):

        self.number = number
        self.port = number
        self.hosts = []

    def __str__(self):

        return f'<PortObject> Port: {self.number}, Hosts: {self.hosts}'

class Protocol:

    def __init__(self, protocol=None, ports=None):

        assert protocol and type(protocol) == str, (
            'Protocol objects expects a string protocool name'
        )

        assert ports and type(ports) == dict, (
            'Protocol objects expect a list of affected ports'
        )

        self.protocol = protocol
        self.ports = ports

    def has_port(self,port):

        if port in self.ports[port]:
            return True
        else:
            return False

    def __str__(self):

        return f'{self.protocol}: {self.ports}'

class ReportItem:

    def __init__(self, plugin_name=None, plugin_id=None, risk_factor=None,
            exploitable=False, exploit_frameworks=[], msf_modules=[]):

        for v in [plugin_name, plugin_id, risk_factor]:
            assert v, 'plugin_name, plugin_id, risk_factor are required'

        self.plugin_name = plugin_name
        self.protocols = {}
        self.risk_factor = risk_factor
        self.plugin_id = plugin_id
        self.exploitable = exploitable
        self.exploit_frameworks = exploit_frameworks
        self.msf_modules = msf_modules

    def append_proto(self, protocol, port):
        'Return true should the port be new for a given protocol'

        if not protocol in self.protocols:

            self.protocols[protocol] = Protocol(protocol, {port:Port(port)})
            return self.protocols[protocol]

        elif not port in self.protocols[protocol].ports:

            self.protocols[protocol].ports[port] = Port(port)
            return self.protocols[protocol]

        else:
            return 0

def parse(input_file=None, output_directory=None, **kwargs):

    # Handle output directory
    bo = base_output_path = helpers.handle_output_directory(
        output_directory
    )

    # Load the Nessus file
    sprint('Loading Nessus file\n')
    tree = ET.parse(input_file)

    # Change to the base output directory
    os.chdir(bo)

    # TODO: Document report structure
    #
    # report[
    #   '<risk_factor>':{
    #       '<plugin_id>':(ReportItem())
    #   }
    # ]

    report = {}

    # For each report item
    for ri in tree.findall('.//ReportItem'):

        attrs = ri.attrib

        # Capturing the pluginID
        plugin_id = pid = attrs['pluginID']

        # Capture the plugin name
         # Mold it to a string suitable for a directory name
        pname = plugin_name = re.sub(
            pname_re, '_', attrs['pluginName']
        ).lower().strip('_')

        # Capture the protocol
        protocol = None
        if 'protocol' in attrs:
            protocol = attrs['protocol']

        # Capture the port
        port = None
        if 'port' in attrs:
            port = attrs['port']

        # =============================================
        # CAPTURE RISK FACTOR & MAKE A DIRECTORY FOR IT
        # =============================================
        #
        # All report items for a given risk factor will be written to disk in a
        # directory by that name.

        # Capture the risk factor
         # Normalize it by making it lower case
        risk_factor = ri.find('./risk_factor').text.lower()
        if not risk_factor in report:
            report[risk_factor] = {}
            os.mkdir(risk_factor)
        os.chdir(risk_factor)

        # ===========================================
        # CAPTURING EXPLOITABLE STATUS AND FRAMEWORKS
        # ===========================================

        frameworks = [
            'canvas',
            'core',
            'd2_elliot',
            'metasploit'
        ]

        verified = []
        msf_modules = []

        # Capture the exploit frameworks
        for fw in frameworks:
            if ri.findall(f'.//exploit_framework_{fw}'):
                verified.append(fw)
        frameworks = verified

        if frameworks:
            exploitable = True

            if 'metasploit' in frameworks:
                
                for ele in ri.findall(f'.//metasploit_name'):
                    msf_modules.append(ele.text)

        else:

            exploitable = False

        # ========================================================================
        # CREATE A REPORT ITEM AND APPEND IT TO THE APPROPRIATE LIST IN THE REPORT
        # ========================================================================

        if pid in report[risk_factor]:
            ri = report[risk_factor][pid]
        else:
            ri = report[risk_factor][pid] = (
                    ReportItem(
                        plugin_name=pname,
                        plugin_id=pid,
                        risk_factor=risk_factor,
                        exploitable=exploitable,
                        exploit_frameworks=frameworks,
                        msf_modules=msf_modules
                    )
                )
        
        proto = ri.append_proto(protocol, port)

        # =======================================================================
        # CHANGE TO BASE OUTPUT DIRECTORY IF THE PROTOCOL HAS ALREADY BEEN PARSED
        # =======================================================================

        if not proto:
            os.chdir(bo)
            continue

        pref = f'Dumping ({port}/{protocol}):'
        pth = f'{risk_factor}/{protocol}/{pname}'
        print('{:22} {}'.format(pref,pth))

        # ==================================
        # CHANGE TO CURRENT PLUGIN DIRECTORY
        # ==================================

        # Enter or create a directory for a given plugin
         # This is where output files will be written
        if not Path(pname).exists():
            os.mkdir(pname)
        os.chdir(pname)

        # ================================================================
        # CAPTURE ALL HOSTS AFFECTED BY A PLUGIN ON A PORT OVER A PROTOCOL
        # ================================================================

        fqdns = []
        ips = []
        for rh in tree.findall(f'.//ReportHost//ReportItem[@pluginID="{plugin_id}"]'\
            f'[@protocol="{protocol}"]'\
            f'[@port="{port}"]/..'):

            # capture primary name of host; could be ip or fqdn
            name = rh.attrib['name']
            if check_ip(name).startswith('ipv'):
                ips.append(name)
            else:
                fqdns.append(name)

            # capture additional address information from tag elements
            tags = ['host-fqdn','host-rdns','host-ip']
            for tag in tags:

                for ele in rh.findall(f'./HostProperties//tag[@name="{tag}"]'):
                    text = ele.text
                    if tag.endswith('ip') and text not in ips:
                        ips.append(text)
                    elif re.search(r'[a-zA-Z]',text) and (
                        not re.match(ipv6_re,text) and not text in fqdns
                    ):
                        fqdns.append(text)

        # ======================
        # WRITING OUTPUT TO DISK
        # ======================

        # Exploit Frameworks
        if ri.exploit_frameworks:
            with open('exploit_frameworks.list','w') as of:              
                for fw in ri.exploit_frameworks:
                    of.write(fw+'\n')

        # Metasploit Modules
        if ri.msf_modules:
            with open('msf_modules.list','w') as of:
                for m in ri.msf_modules:
                    of.write(m+'\n')
       
        # avoid duplication
        # seems redundant; clearly failing to understand something
        ips = [ip for ip in ips if ip not in proto.ports[port].hosts]
        proto.ports[port].hosts += ips
        fqdns = [fqdn for fqdn in fqdns if fqdn not in proto.ports[port].hosts]
        proto.ports[port].hosts += fqdns

        # Write IP addresses and FQDNs to disk in current directory
        for fmt,lst in {'ips':ips,'fqdns':fqdns}.items():

            if lst:

                with open(f'{protocol}_{fmt}.list','a') as outfile:
    
                    for record in lst:
                        outfile.write(record+'\n')

                if port != '0':
    
                    with open(f'{protocol}_{fmt}.sockets','a') as outfile:
    
                        for record in lst:
                            outfile.write(record+f':{port}\n')
    
        # change back to the base directory
        os.chdir(bo)

    return 0
