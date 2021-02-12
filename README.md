# Parsuite

Simple modular framework to support quick creation of file parsers in
Python. See the wiki page for information on creating modules.

I threw this together because I got tired of repeatedly grepping out
the same content for common outputs produced when gunning through
vulnerability assessements and penetration tests. The interface is
extremely primitive but gets the job done, and was written with 
a minimal understanding of argparse. I intend to go back and revisit
it in the future.

# Installation (Python Version >= 3.7)

```
git clone https://github.com/arch4ngel/parsuite
cd parsuite
pip3 install -r requirements.txt
```

## Adding to PATH (Debian)

I use Parsuite enough to add it to my PATH variable like this:

```
mkdir ~/bin
ln -s /path/to/parsuite.py ~/bin/parsuite
```

# Usage

## Listing Modules

Issue the `--help` flag with no arguments. Example:

```
parsuite --help
```

## Getting Module Help

After supplying a module, issue the `--help` flag and help for the specified
module will be returned. Example:

```
parsuite xml_dumper --help
```

# A Note on Output

Output that is unrelated to the parsed content is written to `stderr`. This
allows users to easily redirect the desired content to a file or suppress
error messages.
