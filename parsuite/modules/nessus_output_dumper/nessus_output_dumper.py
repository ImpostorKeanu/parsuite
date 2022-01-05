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
from sys import stderr
from tabulate import tabulate
import IPython

import logging
LOG_FORMAT='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
RE_LETTERS = re.compile('[a-z]', re.I)
logger = logging.getLogger('parsuite.nessus_output_dumper')
handler = logging.StreamHandler(stderr)
handler.setFormatter(logging.Formatter(LOG_FORMAT))
logger.addHandler(handler)

help='Parse a Nessus file and dump the contents to disk by: '\
    'risk_factor > plugin_name'

RISK_FACTORS = ['none','low','medium','high','critical']

args = [
    DefaultArguments.input_file,
    Argument('--output-directory', '-od',
        required=True,
        help='Output directory.'),
    Argument('--plugin-outputs', '-po',
        action='store_true',
        help='''Dump plugin output to disk. This has potential to
        consume vast amounts of disk space. Tread lightly.
        '''),
    Argument('--disable-color-output', '-dc',
        action='store_true',
        help='''Disable color output.
        '''),
    Argument('--debug',
        action='store_true',
        help='Enable debug output.'),
    Argument('--create-port-splits',
        action='store_true',
        help='For each finding, dump a list of IPs by port affected ' \
        'by a finding.'),
    Argument('--risk-factors', '-rfs',
        nargs='+',
        help='Space delimited list of risk factors to dump. Default: %(default)s',
        default=RISK_FACTORS)

]

# plugin_name_re = pname_re = re.compile('(\-|\s|\\|\<|\>|\=|\(|\)|/|\'|\"|\.)+')
plugin_name_re = pname_re = re.compile('(\s|\W)+')

def parse(input_file=None, output_directory=None, plugin_outputs=False,
        disable_color_output=None, debug=None, create_port_splits=False,
        risk_factors=RISK_FACTORS, *args,**kwargs):

    port_splits = create_port_splits

    if disable_color_output:
        color = False
    else:
        from termcolor import colored
        color = True

    if debug:
        logger.setLevel(logging.DEBUG)

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

                value = pref.find('./value').text.split(',')
                logger.debug(f'Total target count: {len(value)}')
                of.write('\n'.join(value))
                break

    # Dump responsive ips
    sprint('Dumping responsive ip addresses')
    with open('responsive_ips.txt','w') as of:

        cache = []

        for tag in tree.xpath('//tag[@name="host-ip"]'):
            ip = tag.text
            if ip not in cache:
                cache.append(ip)

        count = 0
        for value in sorted(cache):
            count += 1
            of.write(value+'\n')

        logger.debug(f'Total responsive IPs: {count}')

    # Dump additional hostnames to disk
    for a in ['netbios-name', 'host-fqdn', 'host-rdns']:

        if a[-1] != 's': fname = a+'s'
        else: fname = a
        fname += '.txt'
        sprint(f'Dumping {a} values to {fname}')

        if tree.xpath(f'//tag[@name="{a}"]'):

            with open(fname.replace('-','_'),'w') as outfile:

                values, count = [], 0
                for ele in tree.xpath(f'//tag[@name="{a}"]'):
                    if not ele.text in values:
                        count += 1
                        values.append(ele.text)
                        outfile.write(ele.text+'\n')

                logger.debug(f'Total of {a} values: {count}')


    # Dump open ports
    sprint('Dumping open ports')
    with open('open_ports.txt','w') as of:

        ports = [
            str(p) for p in sorted(set([int(e) for e in tree.xpath('//@port')])) if p
        ]

        of.write('\n'.join(ports))

        logger.debug(f'Total count of ports: {len(ports)}')

    os.chdir('..')

    # =====================================
    # BEGIN DUMPING THE REPORT BY PLUGIN ID
    # =====================================

    # Dump plugin outputs
    sprint('Dumping report items\n')
    finding_index = {
        'NONE':{},
        'LOW':{},
        'MEDIUM':{},
        'HIGH':{},
        'CRITICAL':{}
    }

    color_lookup = {
            'none':'blue',
            'low':'green',
            'medium':'yellow',
            'high':'red',
            'critical':'magenta'
    }

    # =================
    # PARSE EACH PLUGIN
    # =================

    header = 'Risk       ' \
          'Exploitable    ' \
          'Plugin ID   ' \
          'Plugin Name'

    print(header)
    print('-'*header.__len__())

    # ============================
    # GET PLUGIN ID BY RISK FACTOR
    # ============================

    plugin_ids = []

    for risk_factor in risk_factors:

        if risk_factor == 'none':
            severity = 0
        elif risk_factor == 'low':
            severity = 1
        elif risk_factor == 'medium':
            severity = 2
        elif risk_factor == 'high':
            severity = 3
        elif risk_factor == 'critical':
            severity = 4
        else:
            continue

        plugin_ids += set(tree.xpath(
                f'//ReportItem[@severity="{severity}"]/@pluginID'))

    # ============================================
    # GET LONGEST PID LENGTH FOR OUTPUT FORMATTING
    # ============================================

    pid_len = 0
    for pid in plugin_ids:
        plen = pid.__len__()
        if plen > pid_len: pid_len = plen
    pid_len += 2

    # ==============================
    # PARSE REPORT ITEM BY PLUGIN_ID
    # ==============================

    alerted = []
    for plugin_id in plugin_ids:

        # Report hosts
        rhosts = {}
        protocols = []
        pid = plugin_id

        # ==========================================================
        # EXTRACT PLUGIN IDS, PROTOCOLS, AND INITIALIZE REPORT HOSTS
        # ==========================================================

        for eri in tree.xpath(f'//ReportItem[@pluginID="{plugin_id}"]'):
            ri = FromXML.report_item(eri)

            if ri.risk_factor not in risk_factors: continue

            if not ri.protocol in protocols:
                if not ri.protocol.lower() in ReportHost.PORT_PROTOCOLS:
                    esprint(
                        'Unknown protocol provided. Skipping: {}' \
                        .format(ri.protocol)
                    )
                    continue
                protocols.append(ri.protocol)

            if not plugin_id in alerted:
                alerted.append(plugin_id)

                if color:
                    rf = colored(ri.risk_factor.capitalize(),
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

            # ===================================================
            # CREATE/UPDATE THE OWNER HOST WITH THE AFFECTED PORT
            # ===================================================

            '''
            - Report items (ri) are child elements of hosts
            - The parent of the report item is a host element
            '''

            # Get the host element
            parent = eri.getparent()

            # Get the name of the host
            name = parent.get('name')

            host_ips = parent.xpath('./HostProperties/tag[@name="host-ip"]/text()')

            for host_ip in host_ips:

                rh = rhosts.get(host_ip)

                # Check if the host is already being tracked in rhosts
                if rh:
    
                    # ==================
                    # UPDATE KNOWN RHOST
                    # ==================
    
                    # update the ports list of the target host with the port
                    # of the current report item
                    
                    if not ri.port in rh.ports \
                            .get('number', ri.port.number) \
                            .get('protocol', ri.protocol):
                        rh.append_port(ri.port)
    
                else:
    
                    # ================
                    # CREATE NEW RHOST
                    # ================
    
                    rh = FromXML.report_host(parent)
                    rh.append_port(ri.port)
                    rhosts[host_ip] = rh
    
                # ====================
                # HANDLE PLUGIN OUTPUT
                # ====================
    
                if ri.plugin_output and plugin_outputs:
                    
                    ri.port.plugin_outputs.append_output(
                        plugin_id, ri.plugin_output
                    )

        # =============================
        # HANDLE THE FINDING INDEX ITEM
        # =============================
        '''
        - this is dumped to the findings index in additional_info
        '''

        sev = ri.risk_factor.upper()
        prefix = f'[{sev}] [{plugin_id}] [{len(rhosts.keys())}] '
        suffix = ' '

        exploitable, fws = 'false', 'n/a'

        if ri.exploit_available:
            exploitable = 'true'

        if ri.exploit_frameworks:
            fws = ','.join([fw.upper() for fw in ri.exploit_frameworks])

        finding_index[sev][ri.plugin_name]=(
            {
                'plugin_name': ri.plugin_name,
                'plugin_id': plugin_id,
                'severity': sev,
                'count': len(rhosts.keys()),
                'exploitable': exploitable,
                'exploit_frameworks': fws
            }
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

        out_dir = Path(ri.risk_factor) / str(ri_dir)[:250]
        out_dir.mkdir(parents=True, exist_ok=True)

        # =====================
        # WRITE CONTENT TO DISK
        # =====================

        # Write additional info
        with (out_dir / 'additional_info.txt').open('w') as of:
            of.write(ri.additional_info())

        # Iterate over each protocol
        # These were captured while collecting plugin ids
        for protocol in protocols:

            # Address Lists
            ips = []
            sockets = []
            fqdns = []
            fsockets = []

            # Unique ports affected
            ports = []

            try:

                # Prepare to handle plugin outputs
                if plugin_outputs:

                    plugin_outputs_file = (outdir / f'{protocol}_plugin_outputs.txt').open('w')

                for rhost in rhosts.values():
                    host_ips, host_fqdns = [], []

                    plist = rhost.ports
                    if not plist: continue

                    # ====================
                    # CAPTURE IP ADDRESSES
                    # ====================

                    for addr in rhost.to_addresses(fqdns=True):

                        try:

                            ip = ipaddress.ip_address(addr)
                            host_ips.append(ip)

                            if not ip in ips: ips.append(ip)
                        except:
                            if re.match(fqdn_re, addr):
                                host_fqdns.append(addr)
                                if not addr in fqdns: fqdns.append(addr)
                            else:
                                logger.debug(
                                    f'Failed to handle address: {addr}')
                                continue

                    # ===============
                    # CAPTURE SOCKETS
                    # ===============

                    for port in sorted(plist):

                        if port.number > 0:

                            if not port.number in ports:
                                ports.append(port.number)
    
                            for ip in host_ips:
                                socket = f'{ip}:{port.number}'
                                sockets.append(socket)
    
                            for fqdn in host_fqdns:
                                fsocket = f'{fqdn}:{port.number}'
                                fsockets.append(fsocket)

                        if plugin_outputs and plugin_id in port.plugin_outputs:

                            header = socket
                            if fsocket: header = header+','+fsocket+':'
                            ban = '='*header.__len__()
                            header = f'{ban}{header}{ban}'

                            plugin_output = f'{header}\n\n'+'\n'.join(
                                port.plugin_outputs[plugin_id]
                            )

                            plugin_outputs_file.write('\n\n'+plugin_output)

            except Exception as e:

                logger.debug(f'Unhandled exception occurred: {e}')
                raise e

            finally:

                if plugin_outputs: plugin_outputs_file.close()

            # =====================
            # HANDLE IPv4 ADDRESSES
            # =====================

            ips = [str(ip) for ip in sorted(set(ips))]
            finding_index[sev][ri.plugin_name]['ip_count'] = len(ips)

            # ===================
            # HANDLE IPv4 SOCKETS
            # ===================

            sorted_sockets = []
            for ip in ips:
                for s in [s for s in sockets if s.startswith(ip)]:
                    if not s in sorted_sockets: sorted_sockets.append(s)
            sockets = sorted_sockets

            finding_index[sev][ri.plugin_name]['socket_count'] = len(sockets)

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

            finding_index[sev][ri.plugin_name]['fqdn_count'] = len(fqdns)
            finding_index[sev][ri.plugin_name]['fqdn_socket_count'] = len(fsockets)

            logger.debug(
                f'{ri.plugin_name}: ip_count({len(ips)})  ' \
                f'socket_count({len(sockets)}) fqdn_count({len(fqdns)})' \
                f'fqdn_socket_count({len(fsockets)})'
            )

            # write address lists to disk
            for fmt,lst in {'ips':ips,
                'sockets':sockets,'fqdns':fqdns,
                'fqdn_sockets':fsockets}.items():

                if not lst: continue

                fname = f'{protocol}_{fmt}.list'

                with (out_dir / fname).open('a') as outfile:

                    outfile.write('\n'.join(lst)+'\n')

            # ==================
            # HANDLE PORT SPLITS
            # ==================
            '''
            Creates a new directory that will contain a series of files named
            like "<proto>_<port.number>.list". This is useful when passing the
            list to Metasploit, which doesn't support sockets.
            '''

            if port_splits:

                psplits_dir = out_dir / 'port_splits'
                fpsplits_dir = out_dir / 'fqdn_port_splits'

                psplits_dir.mkdir(parents=True, exist_ok=True)
                fpsplits_dir.mkdir(parents=True, exist_ok=True)

                for port in ports:

                    port = str(port)
                    with (psplits_dir / f'{protocol}_{port}_ips.list').open('a') as outfile:

                        for socket in sockets:
                            addr, sport = socket.split(':')
                            if port == sport: outfile.write(addr+'\n')

                    with (ffpsplits_dir / '{protocol}_{port}_fqdns.list').open('a') as outfile:

                        for socket in fsockets:
                            addr, sport = socket.split(':')
                            if port == sport: outfile.write(addr+'\n')

    adinfo_dir = out_dir / 'additional_info'
    adinfo_dir.mkdir(parents=True, exist_ok=True)

    print()

    sprint('Writing report item index')
    with (adinfo_dir / 'report_item_index.txt').open('w+') as outfile:

        rows = [['Risk Factor', 'Plugin ID', 'Count IPs', 'Count Sockets',
            'Count FQDNs', 'Count FQDN Sockets', 'Exploitable',
            'Exploit Frameworks', 'Plugin Name']]

        for k in ['CRITICAL','HIGH','MEDIUM','LOW','NONE']:

            if finding_index[k]:

                for plugin_name in sorted(
                        list(finding_index[k].keys())):
                    
                    dct = finding_index[k][plugin_name]

                    rows.append([
                        dct.get('severity'),
                        dct.get('plugin_id'),
                        dct.get('ip_count'),
                        dct.get('socket_count'),
                        dct.get('fqdn_count'),
                        dct.get('fqdn_socket_count'),
                        dct.get('exploitable'),
                        dct.get('exploit_frameworks'),
                        dct.get('plugin_name'),
                    ])

        outfile.write(
            tabulate(rows,headers='firstrow')+'\n'
        )

    print()
    return 0
