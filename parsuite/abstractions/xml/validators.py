from lxml import etree as etree

def validate_lxml_tree(tree,*args,**kwargs):
    '''Assure that the tree object is an lxml tree.
    '''
        
    if etree._ElementTree not in tree.__class__.__mro__:

        return False

    else:

        return True

def validate_lxml_module(obj,*args,**kwargs):
    '''Assure that the object is produced by the lxml module
     to prevent any issues when performing XPATH queries.
     '''

    if obj.__class__.__module__ != 'lxml.etree':

        return False

    else:

        return True
