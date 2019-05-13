#!/usr/bin/env python3

from parsuite.abstractions.xml.masscan import *
from xml.etree.ElementTree import ElementTree
from re import match,search
from sys import exit

def parse_masscan(tree,no_services):

    if tree.__class__ != ElementTree:
        raise TypeError(
            'tree should be an xml.etree.ElementTree object'
        )

    report = {}

    status = 'up'
    status_reason = 'masscan-up'

    for ehost in tree.findall('.//state[@state="open"]/../../..'):

        hostnames = []
        addresses = {}
        
        for eaddress in ehost.findall('.//address'):
            addrtype = eaddress.get('addrtype')
            addresses[addrtype+'_address'] = eaddress.get('addr')
        
        host = MasscanHost(**addresses,
            status=status,
            status_reason=status_reason,
            hostnames=hostnames)

        for eport in ehost.findall('.//port'):

            protocol = eport.get('protocol')
            port_id = eport.get('portid')

            estate = eport.find('.//state')
            state = estate.get('state')
            reason = estate.get('reason')

            service = Service(name='masscan-unknown')

            host.append_port(
                Port(number=port_id,protocol=protocol,state=state,
                    reason=reason,service=service)
            )

        if host.ipv4_address:
            report[host.ipv4_address] = host
        elif host.ipv6_address:
            report[host.ipv6_address] = host
        elif host.mac_address:
            report[host.mac_address] = host

    return report
