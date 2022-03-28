#!/usr/bin/env python3

from parsuite.abstractions.xml.nessus import *
from xml.etree.ElementTree import ElementTree
from re import match,search
from copy import copy
import pdb

def parse_http_links(tree,*args,**kwargs):
    
    links = []

    svc_names = set([
            ri.attrib['svc_name'] for ri in tree.findall('.//ReportItem')
            if search(r'http|www',ri.attrib['svc_name']) and ri.attrib['protocol'] == 'tcp'
            ]   
        )

    # Iterate over each plugin id
    for svc_name in svc_names:

        # Get all report items associated with that plugin id and ../ReportHost
        for erhost in tree.findall(f'.//ReportItem[@svc_name="{svc_name}"]/..'):

            rhost = FromXML.report_host(erhost)

            # All ports for this host that support SSL/TLS
            # pluginID 56984 = SSL/TLS Versions Supported
            tunnel_ports = [
                int(v) for v in erhost.xpath('//ReportItem[@pluginID="56984"]/@port')
            ]

            for eri in erhost.findall(f'.//ReportItem[@svc_name="{svc_name}"]'):

                ri = FromXML.report_item(eri)
                
                if ri.port.number in tunnel_ports:
                    scheme = 'https://'
                else:
                    scheme = 'http://'

                for addr in [rhost.ip]+rhost.hostnames:

                    link = scheme+addr+':'+str(ri.port.number)
                    if link in links: continue
                    links.append(link)

    return links

class NessusReport(dict):
    def __init__(self):
        self.plugins = {}

def parse_nessus(tree, no_services, minimize_plugins=True):

    #if tree.__class__ != ElementTree:
    #    raise TypeError(
    #        'tree should be an xml.etree.ElementTree object'
    #    )

    report = NessusReport()

    status = 'up'
    status_reason = 'nessus-up'

    # Get a list of hosts with at least one open port
    # appears as though the "Service detction" plugin family
    # can be used to find this.
    if no_services:
        alive_hosts = tree.findall(
                './/ReportItem[@pluginFamily="Service detection"]/..'
        )
    else:
        alive_hosts = []

    handled = []

    for rhost in tree.findall('.//ReportItem/..'):

        # Assure that the current host has at least one open port
        if alive_hosts and rhost not in alive_hosts: continue

        name = rhost.get('name')
        if name == None: name = None
        
        host_ip = rhost.find('.//tag[@name="host-ip"]')
        if host_ip != None: host_ip = host_ip.text
        else: host_ip = name

        tup = (name, host_ip,)

        if not tup in handled:
            handled.append(tup)
        else:
            continue

        # bush league
        if not name and not host_ip: continue

        if match(r'([0-9]{1,3}\.){3}',host_ip):
            ipv4_address = host_ip
            ipv6_address = None
        else:
            ipv4_address = None
            ipv6_address = host_ip
        
        mac = rhost.find('.//tag[@name="mac-address"]')
        if mac != None: mac = mac.text.split('\n')[0]
        
        hostnames = []
        for k in ['host-fqdn','host-rdns']:

            val = rhost.find(f'.//tag[@name="{k}"]')
            if val != None and val.text not in hostnames:
                hostnames.append(val.text)

        host = Host(ipv4_address=ipv4_address,
            ipv6_address=ipv6_address,
            status=status,
            status_reason=status_reason,
            mac_address=mac,
            hostnames=hostnames)

        for eri in rhost.findall('.//ReportItem'):

            ri = FromXML.report_item(eri, report_host=host)

            if ri.port.number == 0: continue
            
            service = NH.Service(name=ri.service_name)

            # ========================
            # TODO: MAKE THIS NOT YOLO
            # Refine supported protocols.
            # ==========================

            if not ri.protocol.lower() in host.PORT_PROTOCOLS:
                continue

            ports = host.ports \
                .get('protocol', ri.port.protocol) \
                .get('number', ri.port.number)

            if len(ports) > 0:

                ri.port = ports.pop()

                # ==================
                # CAPTURE THE PLUGIN
                # ==================

                # Copy the current report item
                plugin = ReportItem(**{
                    k:getattr(ri, k) for k in
                    ReportItem.STANDARD_PROPERTIES})

                # Unset the port and plugin_output parts
                # because they're associated with an instance
                plugin.port = None
                plugin.plugin_output = None

                # Put the plugin in the plugins dictionary
                if not ri.plugin_id in report.plugins:
                    report.plugins[plugin.plugin_id] = plugin

                if minimize_plugins:

                    # ================================
                    # STRIP PLUGIN DATA TO SAVE MEMORY
                    # ================================

                    for attr, value in plugin.__dict__.items():
                        if value is not None and hasattr(ri, attr) and \
                                attr in ReportItem.MINIMAL_PROPERTIES:
                            setattr(ri, attr, None)

                # Append the report item
                ri.port.report_items.append(ri)

            else:

                host.append_port(ri.port)

        if host.ipv4_address:
            report[host.ipv4_address] = host

        elif host.ipv6_address:
            report[host.ipv6_address] = host

        elif host.mac_address:
            report[host.mac_address] = host

        # =========================
        # FIND ALL SSL/TLS SERVICES
        # =========================
        '''
        - Plugin 56984 enumerates SSL/TLS on all ports for
          a given host.
        '''

        # Iterate over each report host
        for ip, rhost in report.items():

            # ===========================================
            # GATHER PORT NUMBER / PROTOCOL FOR SSL PORTS
            # ===========================================

            # Capture a tuple for each port (port_number, port_protocol)
            port_tups = []
            for port in rhost.ports:

                for ri in port.report_items:
                    if ri.plugin_id == '56984':
                        port_tups.append((ri.port.number, ri.protocol,))

            # =============================================
            # ITERATE EACH PORT AND ADD A WRAPPED ATTRIBUTE
            # =============================================
            '''
            - tunnel attribute indicates that a port is using SSL/TLS.
            '''

            for port, protocol in port_tups:

                for iport in rhost.ports.get('number', port):
                    if not protocol == iport.protocol:
                        continue
                    for ri in iport.report_items:
                        ri.tunnel = True
                        if ri.svc_name == 'http':
                            ri.svc_name = 'https'

    return report

def parse_report_item(ele_report_item):
    '''ele_report_item is a ReportItem element
    '''
    
    ri = ele_report_item
    service = ri.get('svc_name')
    protocol = ri.get('protocol')
    plugin_name = ri.get('pluginName')
    plugin_family = ri.get('pluginFamily')
    port = int(ri.get('port'))
    state = 'open'
    reason = 'nessus-open'

    if port == 0: pass
    
    service = Service(name=service)
    port = Port(number=port,
        protoco=protocol,
        state=state,
        reason=reason,
        service=service)
