from parsuite.core.argument import Argument,DefaultArguments,ArgumentGroup,MutuallyExclusiveArgumentGroup
from parsuite import helpers
from parsuite.core.suffix_printer import *
from sys import stderr,exit
from pathlib import Path
import xml.etree.ElementTree as ET
import argparse
import os
from IPython import embed
import re

help='Dump hosts and open ports from a masscan xml file.'

args = [
    DefaultArguments.input_files,
    # TODO
    Argument('--output-directory','-od',
        required=True,
        help='Output directory to write output.'),
]


GROUP_LINE_REG = r"^Group '(?P<group>.+)' \(RID: (?P<group_rid>[0-9]{1,})\) " \
    r"has member: (?P<domain>.+)\\(?P<username>.+)"

class Normalized:

    def __init__(self,value):
        self.value = value
        self._normalized = Normalized.normalize(value)

    @staticmethod
    def normalize(value):
        normalized = value.replace(' ','_')
        return normalized.lower()

    @property
    def normalized(self):
        return self._normalized

    @normalized.setter
    def normalized(self,value):
        self._normalized = Normalized.normalize(value)

    def __eq__(self,value):
        if self.value == value:
            return True
        else:
            return False

    def __repr__(self):
        return f'{self.__class__}: {self.normalized}'

class List(list):

    def get_by(self,attr,value):

        return List([
            item for item in self if 
            item.__getattribute__(attr) == value
        ])


class MemberList(List):
    pass

class GroupList(List):
    pass

class Group(Normalized):
    # Group 'operators' (RID: 548) has member: domain\username
    REG = r"^Group '(?P<group>.+)' \(RID: (?P<group_rid>[0-9]{1,})\) " \
        r"has member: (?P<domain>.+)?\\(?P<username>.+)"

    def __init__(self, value, type):
        self.members = MemberList()
        self.type = type
        super().__init__(value)

class GroupMember(Normalized):
    pass

def parse(input_files, output_directory, *args, **kwargs):

    helpers.handle_output_directory(output_directory)

    groups = GroupList()

    signatures = [
        '[+] Getting builtin group memberships:',
        '[+] Getting local group memberships:',
        '[+] Getting domain group memberships:'
    ]

    for infile in input_files:

        with open(infile) as f:

            current_groups = None

            for line in f:
                line = line.strip()

                if line in signatures:
                    group_type = line.split(' ')[2]
                    current_groups = groups.get_by('type',group_type)
                    continue
                elif current_groups != None and not line.startswith('Group '):
                    current_groups = None
                elif line.startswith('Group ') and current_groups != None:
                    gd = re.match(Group.REG,line).groupdict()
                    group = gd['group']
                    group_rid = gd['group_rid']
                    domain = gd['domain']

                    member = GroupMember(gd['username'])
                    group_obj = current_groups.get_by('value',group)

                    if not group_obj:
                        group_obj = Group(group,group_type)
                        group_obj.members.append(member)
                        current_groups.append(group_obj)
                    else:
                        group_obj = group_obj[0]
                        if not member in group_obj.members:
                            group_obj.members.append(member)

    embed()
    return 0
