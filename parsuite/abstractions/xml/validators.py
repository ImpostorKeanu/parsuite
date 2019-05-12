from parsuite.abstractions.xml import nessus
import lxml

def validate_lxml_tree(func):

    def validate(tree,*args,**kwargs):
        
        if lxml.etree._ElementTree not in tree.__class__.__mro__:

            raise TypeError(
                'argument must be of type tree'
            )

        else:

            return func(tree,*args,**kwargs)

    return validate
