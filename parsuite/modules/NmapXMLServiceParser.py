from parsuite.core.argument import Argument
from parsuite import helpers
from parsuite.core.suffix_printer import *
import xml.etree.ElementTree as ET
import argparse
import os

help='Accept a XML file generated '\
     'by Nmap and write the output to a local directory structure, '\
     'organized by service, for easy browsing.'

args = [
    Argument('--tcpwrapped', '-tw', action='store_true',
        help='Enable dumping of tcpwrapped services.'),
    Argument('--output-directory', '-od', required=True,
        help='Output directory.')
]

def parse(input_file=None, output_directory=None,
        tcpwrapped=None, **kwargs):

    bo = base_output_path = helpers.handle_output_directory(
        output_directory
    )

    # parse the input file
    tree = ET.parse(input_file)

    os.chdir(output_directory)
    services = tree.findall('.//service')
    handled = []
    change_flag = False

    sprint(f'Parsing {len(services)} services...\n')
    for ser in services:

        if change_flag:
            change_flag = False
            os.chdir(bo)

        sname = service_name = ser.get('name')

        # skip tcpwrapped services unless specified
        if sname == 'tcpwrapped' and not tcpwrapped:
            continue

        # skip any service we've already handled
        if sname in handled:
            continue

        hosts = tree.findall(
            f'.//service[@name="{sname}"]/../../../status[@state="up"]/..'
        )
        
        if hosts:
            handled.append(sname)
            change_flag = True
            os.mkdir(sname)
            os.chdir(sname)
        else:
            continue

        print(f'- {sname}')

        ofs = out_files = {
            'addr_protocol_portid_name':open(
                'name_addr_protocol_portid.txt','w'
            ),
            'addr_protocol_portid':open(
                'addr_protocol_portid.txt','w'
            ),
            'addr_portid':open(
                'addr_portid.txt','w'
            ),
            'addr':open(
                'addr.txt','w'
            )
        }

        for host in hosts:

            addr = host.find('address').get('addr')
            ports = host.findall(
                f'.//service[@name="{sname}"]/..'
            )

            for port in ports:

                portid = port.get('portid')
                protocol = port.get('protocol')

                ofs['addr_protocol_portid_name'].write(
                    f'{addr}:{protocol}:{portid}:{sname}\n'
                )

                ofs['addr_protocol_portid'].write(
                    f'{addr}:{protocol}:{portid}\n'
                )

                ofs['addr_portid'].write(
                    f'{addr}:{portid}\n'
                )

                ofs['addr'].write(
                    f'{addr}\n'
                )

        # close the files
        for handle,f in ofs.items():
            f.close()

    print()
    sprint('Done!')
    print()

    return 0
