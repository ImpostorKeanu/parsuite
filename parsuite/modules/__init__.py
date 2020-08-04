from sys import modules,exit
from pathlib import Path
from importlib.util import spec_from_file_location,module_from_spec
import inspect
from re import match

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

# Sort the file names to organize the modules by name at the main interface
files = sorted(
    [
        f for f in Path(base).glob('**/*.py')
        if f.is_file() and not f.name.startswith('_')
    ]
)

for f in files:

    mname = f.name[:len(f.name)-3]

    # https://stackoverflow.com/questions/67631/how-to-import-a-module-given-the-full-path
    # This is pretty much magic to me
    spec = spec_from_file_location(mname, f.absolute())
    mod = module_from_spec(spec)
    spec.loader.exec_module(mod)
    handles[mname] = mod

