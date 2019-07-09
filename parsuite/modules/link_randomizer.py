from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
from sys import exit,stderr,stdout
import re
from random import randint
from string import ascii_letters as ASCII

help='''Base64 encode a series of values or contents of files. WARNING:
 files are slurped and encoded as a whole.
'''


args = [
    Argument('--link','-l',
        required=True,
        help='''Link to randomize.
        '''),
    Argument('--injection-template','-ij',
        default='<<<:RAND:>>>',
        help='''Template that will be randomized.
        '''),
    Argument('--count','-c',
        required=True,
        type=int,
        help='''Number of links to generate.
        '''
    ),
    Argument('--random-length','-rl',
        default=8,
        type=int,
        help='''Length of random values generated.
        ''')
]

USED_VALUES = []

def gen_rand(length):

    output = ''

    while True:
    
        for n in range(0,length):

            if randint(0,1):
                output += str(randint(0,9))
            else:
                output += ASCII[randint(0,ASCII.__len__()-1)]

        if output not in USED_VALUES: return output

def parse(link,injection_template,count,random_length,
        *args, **kwargs):

    esprint(f'Link Template: {link}')

    template_re = re.escape(injection_template)
    rand_count = re.findall(template_re,link)

    if not rand_count:
        raise ValueError(
            f'Link template does not contain the injection template ({injection_template})'
        )

    rand_count = len(rand_count)

    for ind in range(0,count):

        ilink = link
        vals = []
        for n in range(0,rand_count):
            vals.append(gen_rand(random_length))
        for v in vals:
            ilink = re.sub(template_re,v,ilink,count=1)


        print(ilink)

    return 0
