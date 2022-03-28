#!/usr/bin/env python3
from parsuite.abstractions.xml.nmap import *
from xml.etree.ElementTree import ElementTree
from parsuite.abstractions.xml.generic import network_host as nh
from sys import exit
import re

def parse_http_links(tree,*args,**kwargs):

    links = []

    for ehost in tree.findall('.//host'):

        host = nh.FromXML.host(ehost)
        if host.status != 'up': continue

        hostnames = []
        if host.ipv4_address: hostnames.append(host.ipv4_address)
        if host.ipv6_address: hostnames.append(host.ipv6_address)
        hostnames += host.hostnames

        # BEGIN ENUMERATING PORTS
        for eport in ehost.findall('.//port'):

            port = nh.FromXML.port(eport)

            # ENSURE THIS IS AN HTTP SERVICE
            if not search('http', port.service.name) or port.state != 'open' or (
                    port.protocol != 'tcp'):
                continue

            for hostname in hostnames:

                if not search('https', port.service.name):

                    if port.service.tunnel in ('ssl', 'tls',):
                        link = f'https://{hostname}:{port.number}'
                    else:
                        link = f'http://{hostname}:{port.number}'

                else:

                    link = f'https://{hostname}:{port.number}'

                if not link in links: links.append(link)

    return links

def parse_nmap(tree,require_open_ports):

#    if tree.__class__ != ElementTree:
#        raise TypeError(
#            'tree should be an xml.etree.ElementTree object'
#        )
    
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
            # Initialize service attributes with a name of unknown
            # so that even open ports without a service are returned
            # with a uri-type prefix
            service_attributes = {'name':'unknown'}
            port_number = eport.get('portid')
            protocol = eport.get('protocol')
        
            # Get port state and reason
            eport_state = eport.find('state')
            state = eport_state.get('state')
            reason = eport_state.get('reason')
        
            # Get port service
            eser = eport.find('service')
            if eser != None:

                for attr in Service.ATTRIBUTES:
                    val = eser.get(attr)
                    if val != None: service_attributes[attr]=val

            if service_attributes:
                service = Service(**service_attributes)
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

def iter_nmap(tree,
        only_up=False,
        only_open_ports=True,
        xpath_modifiers=None):

    # ========================
    # PREAPARE XPATH MODIFIERS
    # ========================

    '''Modifiers that will be appended to XPATH queries for
    given resources, i.e.

    {'address':'[@address="192.168.1.1"]'}

    would append the value to the normal address XPATH query
    of './/address' to form './address[@address="192.168.86.1"]'.

    This is useful when working with large XML files and the user
    would like to limit the number of records returned.

    Supported Resources:

    - host
    - address
    - hostname
    - port
    - script
    '''

    queries = {
        'host':'.//host',
        'address':'.//address',
        'hostname':'.//hostname',
        'port':'.//port',
        'script':'.//script'
    }

    xpm = xpath_modifiers = xpath_modifiers or {}

    for k,v in xpm.items():

        if not k in queries: continue
        queries['k'] += v

    from lxml import etree 
    if not isinstance(tree, etree._ElementTree):
        raise TypeError(
            'tree should be an lxml.etree  object'
        )

    # =========================
    # HANDLE REQUIRE OPEN PORTS
    # =========================

    if only_open_ports:

        queries['port'] = \
            './/port/state[@state="open"]/..'

    # =====================
    # BEGIN ITERATING HOSTS
    # =====================

    if only_up:
        taddrs = tree.xpath('//host/status[@state="up"]/../address/@addr')
    else:
        taddrs = tree.xpath('//host/address/@addr')

    for taddr in taddrs:

        for ehost in tree.iterfind(f'//host/address[@addr="{taddr}"]/..'):

            # Getting status
            status = ehost.find('status').get('state')
            status_reason = ehost.find('status').get('reason')
    
            # ===============
            # BUILD ADDRESSES
            # ===============
            
            # Getting addresses
            addresses = {}
            for eaddress in ehost.iterfind(queries['address']):
                addr_type = eaddress.get('addrtype')
                addresses[addr_type+'_address'] = eaddress.get('addr')
            
            # Getting ehostnames
            hostnames = [
                hn.get('name') for hn in ehost.iterfind(queries['hostname'])
            ]
            
            # Create a ehost object
            host = NmapHost(**addresses,
                hostnames=hostnames,
                status=status,
                status_reason=status_reason)
    
            # ===========
            # BUILD PORTS
            # ===========
            
            # Getting ports
            for eport in ehost.iterfind(queries['port']):
                # Initialize service attributes with a name of unknown
                # so that even open ports without a service are returned
                # with a uri-type prefix
                service_attributes = {'name':'unknown'}
                port_number = eport.get('portid')
                protocol = eport.get('protocol')
            
                # Get port state and reason
                eport_state = eport.find('state')
                state = eport_state.get('state')
                reason = eport_state.get('reason')
            
                # Get port service
                eser = eport.find('service')
                if eser != None:
                    for attr in Service.ATTRIBUTES:
                        val = eser.get(attr)
                        if val != None: service_attributes[attr]=val
    
                if service_attributes:
                    service = Service(**service_attributes)
                else:
                    service = None
    
                # =============
                # BUILD SCRIPTS
                # =============
                
                # Get scripts
                scripts = []
                for escript in eport.iterfind(queries['script']):
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

  
            yield host      
