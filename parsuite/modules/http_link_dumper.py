from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
import xml.etree.ElementTree as ET
import argparse
import os
from collections import namedtuple
from re import search

help='Parse either an NMAP or Nessus XML file (.nessus) and dump http '\
    'links relative to port and service. The module will determine if '\
    'the input file is Nessus or NMAP by querying the document for a '\
    '`policyName` element, which indicates a Nessus file. All links '\
    'are printed to stdout.'

args = [
    DefaultArguments.input_files,
]

def parse_nmap(tree, *args, **kwargs):

    for host in tree.findall('.//host'):

        # EXTRACT THE STATUS
        status = host.find('status').attrib['state']
        if status != 'up': continue

        # EXTRACT ADDRESS
        # address = host.find('address').attrib['addr']

        # EXTRACT ALL KNOWN HOSTNAMES
        hostnames = [
            hostname.attrib['name'] for hostname in host.findall('.//hostname')
        ]
        hostnames.append(host.find('address').attrib['addr'])

        # BEGIN ENUMERATING PORTS
        for port in host.findall('.//port'):
            
            # ASSURE THE PORT IS OPEN
            if port.find('.//state').attrib['state'] != 'open':
                continue

            portid = port.attrib['portid']
            service = port.find('.//service')
            sname = service.attrib['name']

            # ASSURE THIS IS AN HTTP SERVICE
            if not search('http',sname): continue

            # DETERMINE IF THERE IS A TUNNEL
            tunnel = None
            if 'tunnel' in service.attrib: tunnel = service.attrib['tunnel']


            for hostname in hostnames:

                if not search('https',sname):

                    if tunnel == 'ssl':
                        print(f'https://{hostname}:{portid}')
                    else:
                        print(f'http://{hostname}:{portid}')

                else:

                    print(f'https://{hostname}:{portid}')

def parse_nessus(tree, *args, **kwargs):
    
    links = []

    # Get a list of plugin ids where the svc_name has the string 'http'
    svc_names = set([
            ri.attrib['svc_name'] for ri in tree.findall('.//ReportItem')
            if search(r'http',ri.attrib['svc_name']) and ri.attrib['protocol'] == 'tcp'
            ]   
        )

    # Iterate over each plugin id
    for svc_name in svc_names:

        # Determine if HTTP/HTTPS
        if search(r'https',svc_name): scheme = 'https://'
        else: scheme = 'http://'

        # Get all report items associated with that plugin id and ../ReportHost
        for rhost in tree.findall(f'.//ReportItem[@svc_name="{svc_name}"]/..'):

            # Get IP address and FQDNs of report host
                # host-ip
                # host-fqdn
                # host-rdns
            host_addresses = []
            for key in ['host-ip','host-fqdn','host-rdns']:
                ele = rhost.find(f'.//tag[@name="{key}"]')
                
                if ele != None and not ele.text in host_addresses:
                    host_addresses.append(ele.text.lower())

            for ri in rhost.findall(f'.//ReportItem[@svc_name="{svc_name}"]'):

                # For each FQDN/IP and port, craft a link
                port = ri.attrib['port']
                for addr in host_addresses:
                    link = scheme+addr+':'+port

                if link and not link in links: links.append(link)

    for link in links: print(link)

def parse(input_files=None, *args, **kwargs):

    for input_file in input_files:
        try:
            tree = ET.parse(input_file)
            if tree.find('.//policyName').__class__ == ET.Element:
                parse_nessus(tree, *args, **kwargs)
            elif tree.find('.//scaninfo').__class__ == ET.Element:
                parse_nmap(tree, *args, **kwargs)
            else: esprint(f'Unknown document provided: {input_file}')
        except Exception as e:
            esprint(f'Unknown exception occurred while parsing: {input_file}')
            print('\n'+e.__str__()+'\n')

    return 0
   
