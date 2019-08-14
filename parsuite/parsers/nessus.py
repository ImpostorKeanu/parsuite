#!/usr/bin/env python3

from parsuite.abstractions.xml.nessus import *
from xml.etree.ElementTree import ElementTree
from re import match,search
import pdb

def parse_http_links(tree,*args,**kwargs):
    
    links = []

    svc_names = set([
            ri.attrib['svc_name'] for ri in tree.findall('.//ReportItem')
            if search(r'http',ri.attrib['svc_name']) and ri.attrib['protocol'] == 'tcp'
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

def parse_nessus(tree,no_services):

    if tree.__class__ != ElementTree:
        raise TypeError(
            'tree should be an xml.etree.ElementTree object'
        )

    report = {}

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

    for rhost in tree.findall('.//ReportItem/..'):

        # Assure that the current host has at least one open port
        if alive_hosts and rhost not in alive_hosts: continue

        name = rhost.get('name')
        if name == None: name = None
        
        host_ip = rhost.find('.//tag[@name="host-ip"]')
        if host_ip != None: host_ip = host_ip.text
        else: host_ip = name

        # bush league
        if not name and not host_ip: continue

        if match(r'([0-9]{1,3}\.){3}',host_ip):
            ipv4_address = host_ip
            ipv6_address = None
        else:
            ipv4_address = None
            ipv6_address = host_ip
        
        mac = rhost.find('.//tag[@name="mac-address"]')
        if mac != None: mac = mac.text
        
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

        for ri in rhost.findall('.//ReportItem'):
            service = ri.get('svc_name')
            protocol = ri.get('protocol')
            plugin_name = ri.get('pluginName')
            plugin_family = ri.get('pluginFamily')
            port = int(ri.get('port'))
            state = 'open'
            reason = 'nessus-open'

            if port == 0: continue
            
            service = NH.Service(name=service)

            host.append_port(
                Port(
                    number=port,protocol=protocol,
                    state=state,reason=reason,service=service
                )
            )

        if host.ipv4_address:
            report[host.ipv4_address] = host
        elif host.ipv6_address:
            report[host.ipv6_address] = host
        elif host.mac_address:
            report[host.mac_address] = host

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
