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

help="""Dump groups and group memberships to disk, using
the filesystem as as basic database for simple searching
using grep and other mechanism.
"""

args = [
    DefaultArguments.input_files,
    # TODO
    Argument('--output-directory','-od',
        required=True,
        help='Output directory to write output.'),
]

class Normalized:
    """Basic class that will normalize a supplied value such that
    it is suitable to be used as a file or directory name. The
    `__eq__` method has been overidden to assure that comparison
    operations occur on the `value` attribute as opposed to
    identifier.
    """

    def __init__(self,value):
        self.value = value
        self._normalized = Normalized.normalize(value)

    @staticmethod
    def normalize(value):
        """Normalize a string. Static method so this capability
        can be accessed by non-Normalized objects.
        """

        normalized = value.replace(' ','_')
        return normalized.lower()

    @property
    def normalized(self):
        """Return the normalized value.
        """

        return self._normalized

    @normalized.setter
    def normalized(self,value):
        """Set the normalized value as an attribute.
        """

        self._normalized = Normalized.normalize(value)

    def __eq__(self,value):
        """Compare the value attribute to the supplied string.
        """

        if self.value == value:
            return True
        else:
            return False

    def __repr__(self):
        """Return a string representation of the object.
        """

        return f'{self.__class__}: {self.normalized}'

class List(list):
    """List object with a `find` method that allows for simplistic
    querying of list items based on value.
    """

    def find(self,attr,value):

        return List([
            item for item in self if 
            item.__getattribute__(attr) == value
        ])


class MemberList(List):
    pass

class GroupList(List):
    """A list of group objects. `append` method has been created
    to facilitate simple creation of groups and addition of users
    to those groups.
    """
    
    def append(self,group,group_type,member):
        
        g = self.find('value',group).find('type',group_type)

        if g and g.__class__ == GroupList: g = group[0]
        else: g = Group(group,group_type)
        g.append_member(member)
        super().append(g)

class Group(Normalized):

    # Group 'operators' (RID: 548) has member: domain\username
    REG = r"^Group '(?P<group>.+)' \(RID: (?P<group_rid>[0-9]{1,})\) " \
        r"has member: (?P<domain>.+)?\\(?P<username>.+)"

    def __init__(self, value, type):
        self.members = MemberList()
        self.type = type
        super().__init__(value)

    def append_member(self,member):

        if not member in self.members:
            self.members.append(GroupMember(member))

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

    # ==========================
    # PARSE EACH ENUM4LINUX FILE
    # ==========================

    sprint('Parsing files. This may take some time....')

    domain = None
    for infile in input_files:

        sprint(f'Parsing: {infile}')

        with open(infile) as f:

            group_type = None

            for line in f:

                line = line.strip()

                # Entering a group type section
                if line in signatures:
                    group_type = line.split(' ')[2]

                # Following 'Getting' signature, each line will begin with 'Group '
                # blank lines indicate that all groups have been parsed. We reset
                # group_type to None to indicate continuation until the next type
                # of group is identified.
                elif not line.startswith('Group '):
                    group_type = None

                # Parse out the Group and Member
                elif line.startswith('Group ') and group_type:
                    gd = re.match(Group.REG,line).groupdict()
                    group = gd['group']
                    group_rid = gd['group_rid']

                    if not domain and gd['domain']:
                        domain = gd['domain']

                    member = gd['username']

                    # Append the new group and member.
                    # Append method handles logic regarding duplicate values
                    groups.append(group=group,
                        group_type=group_type,
                        member=member)

    sprint('Dumping output to disk')

    os.chdir(output_directory)

    # ====================
    # WRITE DOMAIN TO DISK
    # ====================

    if domain: 
        with open('domain.txt','w') as outfile:
            outfile.write(domain+'\n')

    # =============================
    # DUMP EACH DETECTED GROUP TYPE
    # =============================

    for k in ['builtin','local','domain']:

        # ==========================
        # EXTRACT APPROPRIATE GROUPS
        # ==========================

        cgroups = groups.find('type',k)

        # ==========
        # BEGIN DUMP
        # ==========

        if cgroups:

            os.mkdir(k)
            os.chdir(k)

            # ==================================
            # DUMP MANIFESTS OF GROUPS AND USERS
            # ==================================

            written_groups = []
            written_members = []

            groups_file = open(f'groups.txt','w')
            members_file = open(f'members.txt','w')

            sprint(f'Dumping {k} groups...')
            for group in cgroups:

                if group.value not in written_groups:
                    groups_file.write(group.value+'\n')
                    written_groups.append(group.value)

                for member in group.members:
                    if member.value not in written_members:
                        members_file.write(member.value+'\n')
                        written_members.append(member.value)

            groups_file.close()
            members_file.close()

            # ===================
            # DUMP USERS BY GROUP
            # ===================

            os.mkdir(f'members_by_group')
            os.chdir(f'members_by_group')

            for group in cgroups:

                with open(group.normalized+'.users','w') as outfile:

                    for member in group.members:

                        outfile.write(member.value+'\n')

            os.chdir('..')

            # ===================
            # DUMP GROUPS BY USER
            # ===================

            os.mkdir(f'groups_by_member')
            os.chdir(f'groups_by_member')

            for member in written_members:

                with open(Normalized.normalize(member)+'.groups','w') as outfile:

                    for group in cgroups:
                        
                        if group.members.find('value',member):

                            outfile.write(group.value+'\n')

            os.chdir('../..')

    return 0
