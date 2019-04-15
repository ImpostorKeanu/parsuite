#!/usr/bin/env python3

from parsuite.abstractions.xml.nessus import *
from xml.etree.ElementTree import ElementTree
from re import match,search

def parse_nessus(tree,no_services):

    if tree.__class__ != ElementTree:
        raise TypeError(
            'tree should be an xml.etree.ElementTree object'
        )

    report = {}

    status = 'up'
    status_reason = 'nessus-up'

    for rhost in tree.findall('.//ReportItem/..'):

        name = rhost.get('name')
        if name != None: name = name.text
        
        host_ip = rhost.find('.//tag[@name="host-ip"]')
        if host_ip != None: host_ip = ip.text

        if match(r'([0-9]{1,3}\.){3)',host_ip):
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

        host = NessusHost(ipv4_address=ipv4_address,
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
            
            service = Service(name=service)
            host.append_port(
                Port(number=port,protocol=protocol,
                    state=state,reason=reason,service=service)
            )

        if host.ipv4_address:
            report[host.ipv4_address] = host
        elif host.ipv6_address:
            report[host.ipv6_address] = host
        elif host.mac_address:
            report[host.mac_address] = host

    return report
