from parsuite.core.argument import Argument,DefaultArguments
from parsuite.abstractions.xml.nessus import *
from parsuite import helpers
from parsuite.core.suffix_printer import *
from pathlib import Path
from lxml import etree as ET
import argparse
import os
import re
from sys import exit
import ipaddress


help='Parse a Nessus file and dump the contents to disk by: '\
    'risk_factor > plugin_name'

args = [
    DefaultArguments.input_file,
    Argument('--output-directory', '-od', required=True,
        help='Output directory.'),
    Argument('--plugin-outputs', '-po',
        action='store_true',
        help='''Dump plugin output to disk. This has potential to
        consume vast amounts of disk space. Tread lightly.
        '''),
    Argument('--disable-color-output', '-dc',
        action='store_true',
        help='''Disable color output.
        ''')
]

# plugin_name_re = pname_re = re.compile('(\-|\s|\\|\<|\>|\=|\(|\)|/|\'|\"|\.)+')
plugin_name_re = pname_re = re.compile('(\s|\W)+')

def parse(input_file=None, output_directory=None, plugin_outputs=False,
        disable_color_output=None, *args,**kwargs):

    if disable_color_output:
        color = False
    else:
        from termcolor import colored
        color = True
   
    # build output directory
    bo = base_output_path = helpers.handle_output_directory(
        output_directory
    )

    # Load the Nessus file
    sprint('Loading Nessus file')
    tree = ET.parse(input_file)
    os.chdir(bo)

    os.mkdir('additional_info')
    os.chdir('additional_info')

    # Dump target ip addresses
    sprint('Dumping target information (all scanned addresses)')
    with open('target_ips.txt','w') as of:

        # dump all target s to disk    
        for pref in tree.findall('.//preference'):
    
            name = pref.find('./name')
    
            if name.text == 'TARGET':
    
                value = pref.find('./value')
                of.write('\n'.join(value.text.split(',')))
                break

    # Dump responsive ips
    sprint('Dumping responsive ip addresses')
    with open('responsive_ips.txt','w') as of:

        cache = []

        for tag in tree.xpath('//tag[@name="host-ip"]'):
            ip = tag.text
            if ip not in cache:
                cache.append(ip)

        of.write('\n'.join(sorted(cache)))

    # Dump additional hostnames to disk
    for a in ['netbios-name', 'host-fqdn', 'host-rdns']:

        if a[-1] != 's': fname = a+'s'
        else: fname = a
        fname += '.txt'
        sprint(f'Dumping {a} values to {fname}')

        values = {}
        if tree.xpath(f'//tag[@name="{a}"]'):

            with open(fname.replace('-','_'),'w') as outfile:

                values = []
                for ele in tree.xpath(f'//tag[@name="{a}"]'):
                    if not ele.text in values:
                        values.append(ele.text)
                        outfile.write(ele.text+'\n')

    # Dump open ports
    sprint('Dumping open ports')
    with open('open_ports.txt','w') as of:

        ports = [
            str(p) for p in sorted(set([int(e) for e in tree.xpath('//@port')])) if p
        ]

        of.write('\n'.join(ports))

    os.chdir('..')

    # =====================================
    # BEGIN DUMPING THE REPORT BY PLUGIN ID
    # =====================================

    # Dump plugin outputs
    sprint('Dumping report items\n')
    finding_index = {
        'NONE':[],
        'LOW':[],
        'MEDIUM':[],
        'HIGH':[],
        'CRITICAL':[]
    }

    color_lookup = {
            'none':'blue',
            'low':'green',
            'medium':'yellow',
            'high':'red',
            'critical':'magenta'
    }

    # ============================================
    # GET LONGEST PID LENGTH FOR OUTPUT FORMATTING
    # ============================================

    pid_len = 0
    for pid in list(set(tree.xpath('//@pluginID'))):
        plen = pid.__len__()
        if plen > pid_len: pid_len = plen
    pid_len += 2

    # =================
    # PARSE EACH PLUGIN
    # =================

    header = 'Risk       ' \
          'Exploitable    ' \
          'Plugin ID   ' \
          'Plugin Name'

    print(header)
    print('-'*header.__len__())

    for plugin_id in list(set(tree.xpath('//@pluginID'))):

        rhosts = {}
        protocols = []
        alert = True
        pid = plugin_id
        
        # ==========================================================
        # EXTRACT PLUGIN IDS, PROTOCOLS, AND INITIALIZE REPORT HOSTS
        # ==========================================================

        for eri in tree.xpath(f'//ReportItem[@pluginID="{plugin_id}"]'):
            ri = FromXML.report_item(eri)

            if not ri.protocol in protocols:
                protocols.append(ri.protocol)

            if alert:
                alert = False

                if color:
                    rf = colored(ri.risk_factor.upper(),
                            color_lookup[ri.risk_factor])
        
                    if ri.risk_factor.__len__() < 11:
                        rf += ' ' * (11-ri.risk_factor.__len__())

                    if ri.exploitable:
                        rf += colored('True ','red')
                    else:
                        rf += 'False'

                    rf += '      '
                    
                else:
                    
                    rf = ri.risk_factor.upper()
        
                    if ri.risk_factor.__len__() < 11:
                        rf += ' ' * (11-ri.risk_factor.__len__())

                    if ri.exploitable:
                        rf += 'True '
                    else:
                        rf += 'False'

                    rf += '      '
                    
                if pid.__len__() < pid_len:
                    pid += ' ' * (pid_len-pid.__len__())
                    pid += '    '
    
                rf += '    ' + pid
                rf += ri.plugin_name

                print(rf)

            parent = eri.getparent()
            name = parent.get('name')

            if name in rhosts:

                rh = rhosts[name]
                ports = rh.ports.get('number',ri.port.number) \
                    .get('protocol',ri.protocol)
                if not ports:
                    rh.append_port(ri.port)
                else:
                    port = ports[0]
                    
            else:

                rh = FromXML.report_host(parent)
                rh.append_port(ri.port)
                rhosts[name] = rh

            if ri.plugin_output:
                ri.port.plugin_outputs.append_output(
                    plugin_id, ri.plugin_output
                )

        # Handle finding index item
        sev = ri.risk_factor.upper()
        prefix = f'[{sev}] [{plugin_id}] '
        suffix = ' '
        if ri.exploit_available:
            suffix += '[EXPLOITABLE]'
        if ri.exploit_frameworks:
            fws = ','.join([fw.upper() for fw in ri.exploit_frameworks])
            suffix += f'[EXPLOIT FRAMEWORKS: {fws}]'
        finding_index[sev].append(prefix+ri.plugin_name+suffix)
        
        # ================================
        # BUILD REPORT ITEM DIRECTORY NAME
        # ================================

        ri_dir = re.sub(
            pname_re, '_', ri.plugin_name
        ).lower().strip('_')

        # =========================
        # BUILD DIRECTORY STRUCTURE
        # =========================

        if not Path(ri.risk_factor).exists():
            os.mkdir(ri.risk_factor)
        os.chdir(ri.risk_factor)

        if not Path(ri_dir).exists():
            os.mkdir(ri_dir)
        os.chdir(ri_dir)
        
        # =====================
        # WRITE CONTENT TO DISK
        # =====================

        # Additional information
        with open('additional_info.txt','w') as of:
            of.write(ri.additional_info())

        for protocol in protocols:

            # Address Lists
            ips = []
            sockets = []
            fqdns = []
            fsockets = []

            # Unique ports affected
            ports = []

            try:

                if plugin_outputs:
                    
                    plugin_outputs_file = open(f'{protocol}_plugin_outputs.txt','w')
                
                for rhost in rhosts.values():
    
                    plist = rhost.__getattribute__(protocol+'_ports')
                    if plist:
    
                        for addr in rhost.to_addresses(fqdns=True):
    
                            if re.match(ipv4_re,addr):
                                ips.append(addr)
                            elif re.match(ipv6_re,addr):
                                ips.append(addr)
                            elif re.match(fqdn_re,addr):
                                fqdns.append(addr)
                            else:
                                continue
    
                        for number,port in plist.items():
       
                            socket = None
                            fsocket = None
    
                            if number > 0:
                                ports.append(number)
    
                            for ip in ips:
                                if number > 0:
                                    socket = f'{ip}:{port.number}'
                                    sockets.append(socket)
    
                            for fqdn in fqdns:
                                if number > 0:
                                    fsocket = f'{fqdn}:{port.number}'
                                    fsockets.append(fsocket)
    
                            if not socket: continue
    
                            header = socket
                            if fsocket: header = header+','+fsocket+':'
                            ban = '='*header.__len__()
                            header = f'{ban}{header}{ban}'
    
                            if plugin_outputs and plugin_id in port.plugin_outputs:
       
                                plugin_output = f'{header}\n\n'+'\n'.join(
                                    port.plugin_outputs[plugin_id]
                                )
    
                                plugin_outputs_file.write('\n\n'+plugin_output)

            finally:

                if plugin_outputs: 
                    plugin_outputs_file.close()

            # =====================
            # HANDLE IPv4 ADDRESSES
            # =====================

            '''
            
            IPs are now properly sorted before written to disk.

            1. convert each ipv4 string to an ipaddress.ip_address object
            2. sort the ip_address objects
            3. convert each ip_address object back to a string
            '''

            ips = [ip.__str__() for ip in sorted(set([ipaddress.ip_address(ip) for ip in ips]))]

            # ===================
            # HANDLE IPv4 SOCKETS
            # ===================

            '''

            Sockets are now properly sorted before written to disk.

            1. unique string sockets
            2. map each string ip to a list of ports
            3. convert each string ip to an ipaddress.ip_address object
            4. sort the ip_address objects
            5. create a new list of sockets
            '''

            sockets = set(sockets)
            smap = {}

            for s in sockets:
                ip,port = s.split(':')
                if ip not in smap:
                    smap[ip] = [port]
                elif port not in smap[ip]:
                    smap[ip].append(port)

            sips = [ip.__str__() for ip in sorted([ipaddress.ip_address(ip) for ip in set(smap.keys())])]
            sockets = []
            for sip in sips:
                for p in sorted(smap[sip]):
                    s = f'{sip}:{port}'
                    if s not in sockets: sockets.append(s)

            # ============
            # HANDLE PORTS
            # ============
            
            ports = sorted(set(ports))
            if ports:

                # write a list of unique ports to disk
                with open(f'{protocol}_ports.txt','w') as outfile:
                    outfile.write('\n'.join([str(p) for p in ports])+'\n')

            # ============
            # HANDLE FQDNS
            # ============
            
            fqdns = sorted(set(fqdns))
            fsockets = sorted(set(fsockets))

            # write address lists to disk
            for fmt,lst in {'ips':ips,
                'sockets':sockets,'fqdns':fqdns,
                'fqdn_sockets':fsockets}.items():

                if not lst: continue

                fname = f'{protocol}_{fmt}.list'

                with open(fname,'w') as outfile:

                    outfile.write('\n'.join(lst)+'\n')

        os.chdir('../../')

    os.chdir('additional_info')

    print()
    sprint('Writing report item index')
    with open('report_item_index.txt','w') as outfile:

        outfile.write('[Risk Factor] [Plugin ID] Plugin Name [Exploitable]' \
                ' [Exploit Frameworks]\n')

        for k in ['CRITICAL','HIGH','MEDIUM','LOW','NONE']:

            if finding_index[k]:
                outfile.write('\n'.join(finding_index[k])+'\n')

    print()
    return 0
