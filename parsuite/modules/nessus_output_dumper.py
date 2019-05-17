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
from sys import exit


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
        ''')
]

# plugin_name_re = pname_re = re.compile('(\-|\s|\\|\<|\>|\=|\(|\)|/|\'|\"|\.)+')
plugin_name_re = pname_re = re.compile('(\s|\W)+')

def parse(input_file=None, output_directory=None, plugin_outputs=False
        *args,**kwargs):
   
    # build output directory
    bo = base_output_path = helpers.handle_output_directory(
        output_directory
    )
    os.chdir(bo)

    # Load the Nessus file
    sprint('Loading Nessus file')
    tree = ET.parse(input_file)

    # Dump target ip addresses
    sprint('Dumping target information (target addresses)')
    with open('target_ips.txt','w') as of:

        # dump all target s to disk    
        for pref in tree.findall('.//preference'):
    
            name = pref.find('./name')
    
            if name.text == 'TARGET':
    
                value = pref.find('./value')
                of.write('\n'.join(value.text.split(',')))
                break

    # Dump additional hostnames to disk
    for a in ['netbios-name', 'host-fqdn', 'host-rdns']:

        if a[-1] != 's': fname = a+'s'
        else: fname = a
        fname += '.txt'
        sprint(f'Dumping {a} values to {fname}')

        values = {}
        if tree.xpath(f'//tag[@name="{a}"]'):

            with open(fname,'w') as outfile:

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

    # =====================================
    # BEGIN DUMPING THE REPORT BY PLUGIN ID
    # =====================================

    # Dump plugin outputs
    sprint('Dumping plugin outputs\n')
    for plugin_id in list(set(tree.xpath('//@pluginID'))):

        rhosts = {}
        protocols = []
        alert = True

        # ==========================================================
        # EXTRACT PLUGIN IDS, PROTOCOLS, AND INITIALIZE REPORT HOSTS
        # ==========================================================

        for eri in tree.xpath(f'//ReportItem[@pluginID="{plugin_id}"]'):

            ri = FromXML.report_item(eri)

            if not ri.protocol in protocols:
                protocols.append(ri.protocol)

            if alert:
                print(f'- {ri.plugin_name}')
                alert = False

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

            ips = sorted(set((ips)))
            sockets = sorted(set((sockets)))
            fqdns = sorted(set((fqdns)))
            fsockets = sorted(set((fsockets)))
            ports = sorted(set((ports)))

            if ports:

                # write a list of unique ports to disk
                with open(f'{protocol}_ports.txt','w') as outfile:
                    outfile.write('\n'.join([str(p) for p in ports])+'\n')

            # write address lists to disk
            for fmt,lst in {'ips':ips,
                'sockets':sockets,'fqdns':fqdns,
                'fqdn_sockets':fsockets}.items():

                if not lst: continue

                fname = f'{protocol}_{fmt}.list'

                with open(fname,'w') as outfile:

                    outfile.write('\n'.join(lst)+'\n')

        os.chdir('../../')

    print()
    return 0
