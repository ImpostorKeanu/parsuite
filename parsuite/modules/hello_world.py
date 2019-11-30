from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *

help='Hello world!'
args=[
            Argument('--my-name','-mn',
                        help='Your name',
                                required=True)
            ]

def parse(my_name,*args,**kwargs):
        print(f'Hello world! My name is {my_name}!')
