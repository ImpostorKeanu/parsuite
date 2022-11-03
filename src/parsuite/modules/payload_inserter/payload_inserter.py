from parsuite.core.argument import Argument
from parsuite import helpers
from parsuite.core.suffix_printer import *
from hashlib import md5

help = ('Replace all instances of a signature in a template file. '
        'Useful in situations when a long payload needs to be inserted '
        'into a file, such as when working with hex encoded shellcode '
        'for stageless payloads.')

args = [
    Argument('--template-file','-tf',
        required=True,
        help=('Template file containing instances of --signature. '
              'All instances of --signature will be replaced with '
              'content from --payload-file.')),
    Argument('--payload-file','-pf',
        required=True,
        help=('File containing content that will replace --signature '
              'instances found in --template-file.')),
    Argument('--output-file','-of',
        required=True,
        help='File that will receive output.'),
    Argument('--signature','-s',
        required=True,
        help=('Signature string. Must be at the beginning of a '
              'line on it\'s own. This value will be replayed with the '
              'payload'))
]

def parse(template_file=None, payload_file=None, signature=None,
        output_file=None, *args, **kwargs):

    esprint('Checking input files')
    helpers.validate_input_files([template_file, payload_file])

    esprint('Parsing the payload file')
    with open(payload_file, 'rb') as infile:
        payload = infile.read()[:-1]

    esprint('Opening and parsing the template file')
    with open(template_file, 'rb') as template:
        orig = template.read()
        o_hash = md5()
        o_hash.update(orig)

        buff = orig.replace(bytes(signature,'utf8'), payload, -1)
        b_hash = md5()
        b_hash.update(buff)

    if o_hash.digest() != b_hash.digest():
        esprint('File updated')
        esprint('Writing output file')
        with open(output_file,'wb') as outfile:
            outfile.write(buff)
    else:
        esprint('Signature undetected!')
        esprint('File unchanged.')