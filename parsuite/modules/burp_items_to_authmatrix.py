from parsuite.core.argument import Argument,DefaultArguments
from parsuite import helpers
from parsuite.core.suffix_printer import *
from parsuite.abstractions.xml.burp import *
from lxml import etree as ET
from http.cookies import SimpleCookie
from base64 import b64encode
import json

def encode(s):
    return b64encode(bytes(s,'utf8')).decode('utf8')

help = '''Parse an XML file containing Burp items and return a
JSON statefile for AuthMatrix. Each item element of the input
file must contain a "username" child element and one or more "role"
child elements. WARNING: THE CHILD AND USERNAME ELEMENTS MUST BE ADDED
TO EACH ITEM MANUALLY!!!
'''

args = [
    DefaultArguments.input_file,
    Argument('--pretty-print','-pp',
        action='store_true',
        help='Pretty print the results.'),
]

class Role:

    def __init__(self,name,index,column,deleted=False,
            singleUser=False):

        self.index = index
        self.column = column
        self.name = name
        self.deleted = deleted
        self.singleUser = singleUser

    def __dict__(self):

        return dict(index=self.index,column=self.column,
                name=self.name,deleted=self.deleted,
                singleUser=self.singleUser)

def parse(input_file, pretty_print, **kwargs):

    if pretty_print: pretty_print=4
    else: pretty_print=None
    
    # json template    
    dct = {
            'version':'0.8',
            'arrayOfUsers': []
    }

    tree = ET.parse(input_file)

    # ==============================
    # LOAD ALL ROLES FROM ITEMS FILE
    # ==============================
    
    roles = {}

    for role in tree.xpath('//role'):

        if role.text in roles: continue

        if not roles: indcol = 0
        else: indcol = roles.__len__()

        roles[role.text] = Role(name=role.text, index=indcol, 
                column=indcol)

    dct['arrayOfRoles'] = [rv.__dict__() for rk,rv in roles.items()]

    # ====================
    # PARSE EACH BURP ITEM
    # ====================

    counter = 0
    for item in tree.xpath('//item'):

        try:

            # ===================
            # BUILD THE BURP ITEM
            # ===================

            username = item.find('username')
            user_roles = item.xpath('.//role')

            if username is None:
                raise Exception(
                    'username element not found'
                )

            if user_roles is None:
                raise Exception(
                    'one or role elements not found'
                )

            # unpack the roles
            user_roles = [ele.text for ele in user_roles]
            user_roles = {rval.index.__str__():(rkey in user_roles) for
                    rkey,rval in roles.items()}

            item = Item.from_lxml(item)

            # ============================
            # BUILD COOKIES FROM BURP ITEM
            # ============================

            cookies = SimpleCookie()

            # Load request cookies
            req_cookies = item.request.headers.get('Cookie') or \
                    item.request.headers.get('cookie')

            if req_cookies: cookies.load(req_cookies)

            # Load response cookies
            res_cookies = item.response.headers.get('Set-Cookie') or \
                    item.response.headers.get('set-cookie')

            if res_cookies: cookies.load(res_cookies)

            # base64 encode the final output
            cookies = encode(
                    cookies.output(attrs=[],header='',sep=';')
                )

            dct['arrayOfUsers'].append(
                {
                    'name':username.text,
                    'index':counter,
                    'tableRow':counter,
                    'cookiesBase64':cookies,
                    'headersBase64':[],
                    'roles':user_roles
                }
            )

        except Exception as e:

            esprint(f'Failed to parse item #{counter}: {e}')

        counter += 1

    print(json.dumps(dct,indent=pretty_print))

    return 0
