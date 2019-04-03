class Argument:


    def __init__(self, *args, **kwargs):

        self.pargs = args
        self.kwargs = kwargs
    
class DefaultArguments:
    
    input_file = Argument('--input-file','-if',
        required=True,
        help='Input file to parse.')
    
    input_files = Argument('--input-files','-ifs',
        required=True,
        help='Input files to parse.',
        nargs='+')
