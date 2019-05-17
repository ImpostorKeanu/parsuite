from parsuite.abstractions.xml import validators as xv

def validate_lxml_tree(func):

    def wrapper(tree,*args,**kwargs):

        if not xv.validate_lxml_tree(tree,*args,**kwargs):

            raise TypeError(
                'argument must be of type tree'
            )

        else:

            return func(tree,*args,**kwargs)

    return wrapper

def validate_lxml_module(func):

    def wrapper(obj,*args,**kwargs):

        if not xv.validate_lxml_module(obj,*args,**kwargs):

            raise TypeError(
                'argument object must originate from the lxml module'
            )

        else:

            return func(obj,*args,**kwargs)

    return wrapper


