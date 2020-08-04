from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
from sys import exit,stderr,stdout
import re
from random import randint
from string import ascii_letters as ASCII

help='''Accept a string as input and replace a template with
random values.
'''
args = [
    Argument('--string','-s',
        required=True,
        help='''Link to randomize.
        '''),
    Argument('--injection-template','-ij',
        default='<<<:RAND:>>>',
        help='''Template that will be randomized.
        Default: %(default)s'''),
    Argument('--count','-c',
        default=1,
        type=int,
        help='''Number of strings to generate.
        '''
    ),
    Argument('--random-length','-rl',
        default=8,
        type=int,
        help='''Length of random values generated.
        Default: %(default)s''')
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

def parse(string,injection_template,count,random_length,
        *args, **kwargs):

    esprint(f'String Template: {string}')

    template_re = re.escape(injection_template)
    rand_count = re.findall(template_re,string)

    if not rand_count:
        raise ValueError(
            f'Link template does not contain the injection template ({injection_template})'
        )

    rand_count = len(rand_count)

    for ind in range(0,count):

        istring = string
        vals = []
        for n in range(0,rand_count):
            vals.append(gen_rand(random_length))
        for v in vals:
            istring = re.sub(template_re,v,istring,count=1)


        print(istring)

    return 0
