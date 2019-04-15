#!/usr/bin/env python3
from parsuite.abstractions.xml.nmap import *
from xml.etree.ElementTree import ElementTree

def parse_nmap(tree,require_open_ports):

    if tree.__class__ != ElementTree:
        raise TypeError(
            'tree should be an xml.etree.ElementTree object'
        )
    
    report = {}

    for ehost in tree.findall('.//host'):
    
        # Getting status
        status = ehost.find('status').get('state')
        status_reason = ehost.find('status').get('reason')
        
        # Getting addresses
        addresses = {}
        for eaddress in ehost.findall('.//address'):
            addr_type = eaddress.get('addrtype')
            addresses[addr_type+'_address'] = eaddress.get('addr')
        
        # Getting ehostnames
        hostnames = [
            hn.get('name') for hn in ehost.findall('.//hostname')
        ]
        
        # Create a ehost object
        host = NmapHost(**addresses,
            hostnames=hostnames,
            status=status,
            status_reason=status_reason)
        
        # Getting ports
        for eport in ehost.findall('.//port'):
            port_number = eport.get('portid')
            protocol = eport.get('protocol')
        
            # Get port state and reason
            eport_state = eport.find('state')
            state = eport_state.get('state')
            reason = eport_state.get('reason')
        
            # Get port service
            eser = eport.find('service')
            if eser != None:
                attributes = {}
                for attr in Service.ATTRIBUTES:
                    val = eser.get(attr)
                    if val != None: attributes[attr]=val

            if attributes:
                service = Service(**attributes)
            else:
                service = None
            
            # Get scripts
            scripts = []
            for escript in eport.findall('.//script'):
                scripts.append(
                    Script(
                        id=escript.get('id'),
                        output=escript.get('output')
                    )
                )
        
               # Append the port object
            host.append_port(
                Port(number=port_number, protocol=protocol,
                    state=state, reason=reason, service=service,
                    scripts=scripts)
            )
        
        if host.ipv4_address:
            report[host.ipv4_address] = host
        elif host.ipv6_address:
            report[host.ipv6_address] = host
        elif host.mac_address:
            report[host.mac_address] = host
    
    return report
