from sys import modules,exit
from pathlib import Path
from importlib.util import spec_from_file_location,module_from_spec
import inspect
from re import match

import warnings
warnings.filterwarnings('ignore')

# =====================================
# GET THE PATH TO THE MODULES DIRECTORY
# =====================================
m = match(r'/.+/',inspect.getfile(
        inspect.currentframe()
    )
)

# ========================
# DYNAMICALLY LOAD MODULES
# ========================

# Catch each module in a dictionary to be read by the main program
handles = {}

base = m.string[m.start():m.end()]

files = []
for d in Path(base).iterdir():

    if not d.is_dir() or d.name.startswith('__'): continue

    module_files = [
        f for f in d.glob('*.py') if not f.name.startswith('_')
    ]

    count = len(module_files)
    if count < 1 or count > 1:
        raise Exception(
            'Root module directories must contain a single .py file.'
            f' {d}'
        )

    if module_files[0].is_file() and not module_files[0] \
            .name.startswith('_'):
        files.append(module_files[0])

files = sorted(files)

for f in files:

    mname = f.name[:len(f.name)-3]

    # https://stackoverflow.com/questions/67631/how-to-import-a-module-given-the-full-path
    # This is pretty much magic to me
    spec = spec_from_file_location(mname, f.absolute())
    mod = module_from_spec(spec)
    spec.loader.exec_module(mod)
    handles[mname] = mod

