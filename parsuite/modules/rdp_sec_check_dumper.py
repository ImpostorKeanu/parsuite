from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
import argparse
import os
import re

help='Parse files containing NTLMv2 hashes in the commong format produced '\
    'by Responder and Impacket and dump them to stdout. Messages printed '\
    'that are not hashes are dumped to stderr. Use the -du flag to disable '\
    'uniquing of username/domain combinations.'

ISSUE_CHOICES=['nla_not_enforced',
#'insecure_encryption_levels_supported',
'rdp_supported_mitm']

args = [
    DefaultArguments.input_files,
    Argument('--issues-to-dump','-i',
        nargs='+',
        choices = ISSUE_CHOICES+['all'],
        required=True,
        help='Select which issues to dump by.'),
    Argument('--hosts-only',
        action='store_true',
        help='Dump only hosts affected by the issues')
]

class RDPHost:

    def __init__(self,output_block):

        self.issues = []
        for line in output_block:

            # extract the target, ip, and port for the host
            line_match = False
            for tag in ['Target','IP','Port']:

                match = re.match(f'{tag}:\s+(?P<{tag}>.+)',line)
                if match:
                    self.__setattr__(tag.lower(),match.groupdict()[tag])
                    line_match = True
                    break

            if line_match: continue
            
            # extract protocol support from summary
            match = re.search(
                r'PROTOCOL_(?P<protocol>RDP|SSL|HYBRID).+:\s+(?P<supported>.+)',
                line
            )
            if match:
                gd = match.groupdict()
                if gd['supported'] == 'TRUE': supported = True
                else: supported = False
                self.__setattr__(f'protocol_{gd["protocol"].lower()}_supported',supported)
                continue

            # extract encryption support from summary
            match = re.search(
                r'ENCRYPTION_METHOD_(?P<method>(NONE|40BIT|128BIT|56BIT|FIPS)).+:\s+(?P<supported>.+)',
                line
            )
            if match:
                gd = match.groupdict()
                if gd['supported'] == 'TRUE': supported = True
                else: supported = False
                self.__setattr__(f'encryption_method_{gd["method"].lower()}_supported',supported)
                continue

            # extract summary of security issues
            match = re.search(
                r'has issue (?P<issue>.+)',
                line
            )
            if match:
                issue = match.groupdict()['issue']
                self.issues.append(issue.lower())

    def __str__(self):
        return str(self.__dict__)

    def dump_nla_not_enforced(self):

        output = []
        if self.protocol_rdp_supported:
            output.append('RDP Security Supported')
        if self.protocol_ssl_supported:
            output.append('SSL Security Supported')

        if output:
            sprint(f'{self.ip} Supports Non-NLA Mechanisms:')
            print('\n- '+('\n- '.join(output))+'\n')

    def dump_insecure_encryption_levels_supported(self):

        output = []
        if self.encryption_method_40bit_supported:
            output.append('40bit Encryption Method')
        if self.encryption_method_56bit_supported:
            output.append('56bit Encryption Method')

        if output:
            sprint(f'{self.ip} Supports Insecure Encryption Levels:')
            print('\n- '+('\n- '.join(output))+'\n')

    def dump_rdp_supported_mitm(self):

        if self.protocol_rdp_supported:
            sprint(f'{self.ip} Supports RDP Security (Vulnerable to MITM)')

def parse(input_files=None, issues_to_dump=None, hosts_only=False, **kwargs):

    report = {}
    esprint(f'Parsing hash files: {",".join(input_files)}')
    for input_file in input_files:

        with open(input_file) as infile:

            target_block = []
            for line in infile:

                if re.search('\[W\]',line):
                    target_block = []
                    continue

                line = line.strip()

                if line.startswith('Target:'):

                    if not target_block:
                        target_block.append(line.strip())
                        continue

                    host = RDPHost(target_block)
                    if host: report[host.ip] = host
                    target_block = [line]

                elif target_block:

                    target_block.append(line)

    nla_not_enforced = []
    insecure_encryption_levels_supported = []
    rdp_supported_mitm = []
    for ip,rdp_host in report.items():

        if rdp_host.protocol_rdp_supported or rdp_host.protocol_ssl_supported:
            nla_not_enforced.append(rdp_host)

        if rdp_host.protocol_rdp_supported:
            rdp_supported_mitm.append(rdp_host)

        for key in ['40bit','56bit']:
            if rdp_host.__getattribute__(f'encryption_method_{key}_supported'):
                insecure_encryption_levels_supported.append(rdp_host)

    if 'all' in issues_to_dump: issues_to_dump = ISSUE_CHOICES

    for key in issues_to_dump:

        lst = locals()[key]
        if hosts_only:
            for host in lst: print(host.ip)
        else:
            sprint(f'Dumping issue type: {key}')
            for host in lst:
                host.__getattribute__('dump_'+key)()

    esprint('Finished!')
