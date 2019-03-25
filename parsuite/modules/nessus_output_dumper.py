from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
from pathlib import Path
from IPython import embed
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
        self.ips = []
        self.fqdns = []

    def append_host(self, host):
        '''
        Append a host to the appropriate list, ips or fqdns. Provides logic to
        determine the type of host being handled.
        '''

        if (re.match(ipv4_re,host) or re.match(ipv6_re,host)) and host not in self.ips:
            self.ips.append(host)
        elif re.search(r'[a-zA-Z]',host) and not re.match(ipv6_re,host) and not (
            host in self.fqdns):
            self.fqdns.append(host)

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

    def __init__(self, plugin_name, plugin_id, risk_factor,
            exploitable, synopsis, solution, description,
            plugin_type, plugin_output, exploit_frameworks=[],
            msf_modules=[],**kwargs):

        for v in [plugin_name, plugin_id, risk_factor]:
            assert v, 'plugin_name, plugin_id, risk_factor are required'

        self.plugin_name = plugin_name
        self.protocols = {}
        self.risk_factor = risk_factor
        self.plugin_id = plugin_id
        self.exploitable = exploitable
        self.exploit_frameworks = exploit_frameworks
        self.msf_modules = msf_modules
        self.synopsis = synopsis
        self.solution = solution
        self.description = description
        self.plugin_type = plugin_type
        self.plugin_outputs = [plugin_output]

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

    def additional_info(self):

        output = f'# synopsis\n\n{str(self.__getattribute__("synopsis"))}'
        for k in ['solution','description', 'plugin_type']:

            output += f'\n\n# {k}\n\n{str(self.__getattribute__(k))}'

        if self.exploit_frameworks:

            frameworks = '\n'.join(self.exploit_frameworks)
            output += f'\n\n# exploit_frameworks:\n\n{frameworks}'

        if self.msf_modules:

            modules = '\n'.join(self.msf_modules)
            output += f'\n\n# msf_modules:\n\n{modules}'

        output += '\n'

        if self.plugin_outputs:
            for op in set(self.plugin_outputs):
                output += f'\n{op}'
            output += '\n'

        return output+'\n'

class Report(dict):

    def dump(self, output_directory):

        # Handle output directory
        bo = base_output_path = helpers.handle_output_directory(
            output_directory
        )

        os.chdir(bo)

        risk_factors = self.keys()

        for risk_factor, plugin_items in self.items():

            # =================================
            # CREATE AND ENTER OUTPUT DIRECTORY
            # =================================
            
            os.chdir(bo)
            os.mkdir(risk_factor)
            os.chdir(risk_factor)

            for plugin_id, report_item in plugin_items.items():
            
                # =================================
                # CREATE AND ENTER PLUGIN DIRECTORY
                # =================================

                if not Path(report_item.plugin_name).exists():
                    os.mkdir(report_item.plugin_name)

                os.chdir(report_item.plugin_name)

                # =======================================================
                # WRITE EXPLOIT FRAMEWORKS AND METASPLOIT MODULES TO DISK
                # =======================================================

#                if report_item.exploit_frameworks:
#                    with open('exploit_frameworks.list','w') as of:              
#                        for fw in ri.exploit_frameworks:
#                            of.write(fw+'\n')
#    
#                if report_item.msf_modules:
#                    with open('msf_modules.list','w') as of:
#                        for m in ri.msf_modules:
#                            of.write(m+'\n')

                with open('additional_info.txt','w') as outfile:
                    outfile.write(report_item.additional_info())

                for protocol_text, protocol in report_item.protocols.items():

                    for port_number, port in protocol.ports.items():

                        # =======================
                        # WRITE IPs/FQDNs TO DISK
                        # =======================
    
                        # Write IP addresses and FQDNs to disk in current directory
                        for fmt,lst in {'ips':port.ips,
                                'fqdns':port.fqdns}.items():
    
                            if lst:

                                # ==================================
                                # AVOID DUPLICATE ADDRESSES IN LISTS
                                # ==================================
                                #
                                # NOTE: Duplicate addresses were being dumped to list files
                                # because the report structure relies on ports to create
                                # lists. This means a list of fqdns/ips would be appended
                                # multiple times, once for each port associated with a
                                # given report item. This inefficiency is my fault but
                                # whatever.
                                #

                                lst_name = f'{protocol_text}_{fmt}.list'

                                if Path(lst_name).exists(): 

                                    with open(lst_name) as infile:
                                        buff = [l.strip() for l in infile]

                                else: buff = None         
            
                                with open(lst_name,'a') as outfile:

                                    if buff:
        
                                        for record in lst:
                                            if not record in buff:
                                                outfile.write(record+'\n')
                                   
                                    else:

                                        for record in lst:
                                            outfile.write(record+'\n')
    
                                if port != '0':
        
                                    with open(f'{protocol_text}_{fmt}.sockets','a') as outfile:
        
                                        for record in lst:
                                            outfile.write(record+f':{port_number}\n')

                os.chdir('..')
        

def parse(input_file=None, output_directory=None, **kwargs):

    # Load the Nessus file
    sprint('Loading Nessus file')
    tree = ET.parse(input_file)

    # TODO: Document report structure
    #
    # report[
    #   '<risk_factor>':{
    #       '<plugin_id>':(ReportItem())
    #   }
    # ]

    report = Report()

    sprint('Parsing the Nessus file. This will take time...')

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

        # ==============================
        # EXTRACT ADDITIONAL INFORMATION
        # ==============================

        plugin_output = ri.find(f'./plugin_output')

        if plugin_output != None: plugin_output = plugin_output.text

        additional_attributes = {
            'synopsis':None,
            'solution':None,
            'description':None,
            'plugin_type':None,
        }

        for add_attr in additional_attributes.keys():

            add_ele = ri.find(f'./{add_attr}')

            if add_ele != None:
                additional_attributes[add_attr] = add_ele.text
            else:
                additional_attributes[add_attr] = None

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
                        msf_modules=msf_modules,
                        plugin_output=plugin_output,
                        **additional_attributes
                    )
                )
        
        proto = ri.append_proto(protocol, port)
        ri.plugin_outputs.append(plugin_output)
        if not proto: continue
        port = proto.ports[port]

        # ================================================================
        # CAPTURE ALL HOSTS AFFECTED BY A PLUGIN ON A PORT OVER A PROTOCOL
        # ================================================================

        pref = f'Parsing ({port.number}/{protocol}):'
        pth = f'{risk_factor}/{protocol}/' \
            f'{ri.plugin_name}'
        print('{:22} {}'.format(pref,pth))

        ips = []
        for rh in tree.findall(f'.//ReportHost//ReportItem[@pluginID="{plugin_id}"]'\
            f'[@protocol="{protocol}"]'\
            f'[@port="{port.number}"]/..'):

            # capture primary name of host; could be ip or fqdn
            port.append_host(rh.attrib['name'])

            # capture additional address information from tag elements
            tags = ['host-fqdn','host-rdns','host-ip']
            for tag in tags:

                for ele in rh.findall(f'./HostProperties//tag[@name="{tag}"]'):
                    port.append_host(ele.text)

    sprint('Parsing finished...dumping contents to disk')
    report.dump(output_directory)

    return 0
