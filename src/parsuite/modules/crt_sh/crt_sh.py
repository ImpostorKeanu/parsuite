from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
import argparse
import os
import requests
import pprint
import pdb

help='Query crt.sh and dump output to disk'

args = [
    Argument('--queries','-qs',
        nargs='+',
        required=True,
        help='Query values.'
    ),
    Argument('--format','-f',
        choices=['json','name_list'],
        default='name_list',
        help='Output format.'
    ),
    Argument('--base-url','-bu',
        default='https://crt.sh/',
        help='Target url for request, without query string'),
    Argument('--pretty-print','-pp',
        action='store_false',
        help='Pretty print JSON output')
]

def parse(queries=[], format='name_list', base_url='', pretty_print=True,
        *args, **kwargs):

    queries = list(set(queries))
    buff = []

    # =================
    # MAKE THE REQUESTS
    # =================

    for ind in range(0,queries.__len__()):

        # ======================
        # CRAFT QUERY PARAMETERS
        # ======================

        query = queries[ind]
        params={'output':'json','q':query}
        esprint(f'R{ind}: {query}')

        # ================
        # MAKE THE REQUEST
        # ================

        try:
            resp = requests.get(base_url,params=params)

            if resp.status_code != 200:

                esprint(
                    f'Failed to query {query}; Bad status code: ' +
                    str(resp.status_code)
                )

            elif resp.text and resp.text.find('Unsupported use') > -1:

                esprint(f'Bad query detected: {query}\n\n{resp.text}\n\n')

            else:

                buff.append(resp.json())

        except Exception as e:
            esprint(f'Unhandled exception: {e}')
            esprint('Continuing to next query')
            continue

    # ==================================
    # FLATTEN THE MULTIDIMENSIONAL ARRAY
    # ==================================
        
    buff = [j for sub in buff for j in sub]

    esprint('All requests complete')

    # =================================
    # FORMAT AND DUMP RESULTS TO STDOUT
    # =================================

    if format == 'json':

        # Flatten the array of JSON objects
        if pretty_print:
            printer = pprint.PrettyPrinter()
            printer(pprint(buff))
        else:
            print(buff)

    else:

        print('\n'.join(set([o['name_value'] for o in buff])))

    esprint('Finished!')

    return 0
