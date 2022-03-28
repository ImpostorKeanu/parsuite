#!/usr/bin/env python3

from re import search,match,compile
from sys import exit
from parsuite import decorators
import pdb
from copy import copy
from netaddr import EUI as MAC, IPAddress
from parsuite.helpers import slugified, SLUGIFY_DEFAULTS_TAG, AttrDict
from parsuite.abstractions.xml.generic.exceptions import *
from functools import wraps
from copy import deepcopy

ve = decorators.validate_lxml_module

def validate_port(func):
    '''Decorator used to enforce type on port objects.
    '''

    def validate(self,port,*args,**kwargs):

        if port.__class__ == Port or Port in port.__class__.__bases__:
            return func(self,port,*args,**kwargs)
        else:
            raise TypeError(
                'PortList values must inherit from Port'
            )

    return validate

vp = validate_port

class Script(AttrDict):
    '''A basic representation of an Nmap script.

    nmap.dtd specification:

    <!ELEMENT script	(#PCDATA|table|elem)* >
    <!ATTLIST script	
	id	CDATA	#REQUIRED
	output	CDATA	#REQUIRED
    >
    '''

    DICT_ATTRS = [
        'id',
        'id_slug',
        'san_dns_names',
        'output']

    def __init__(self,id,output):

        self.id = id
        self.output = output

    @property
    @slugified()
    def id_slug(self):
        return self.id

    @property
    def san_dns_names(self):
        if not self.output: return []
        dns_names = []
        for line in self.output.split('\n'):
            if not line.startswith('Subject Alternative Name'): continue
            dns_names += ' '.join([
                    v.lower() for v in line.split('DNS:')[1:]
                ]).split(', ')
        return dns_names

class Service(AttrDict):
    '''A basic representation of an Nmap service.

    nmap.dtd specification:

    <!ELEMENT service	(cpe*) >
    <!ATTLIST service
    			name		CDATA		    #REQUIRED
    			conf		%service_confs;	#REQUIRED
                method      (table|probed)  #REQUIRED
                version     CDATA           #IMPLIED
                product     CDATA           #IMPLIED
                extrainfo   CDATA           #IMPLIED
    			tunnel		(ssl)		    #IMPLIED
    			proto		(rpc)		    #IMPLIED
    			rpcnum		%attr_numeric;	#IMPLIED
    			lowver		%attr_numeric;	#IMPLIED
    			highver		%attr_numeric;	#IMPLIED
                hostname    CDATA           #IMPLIED
                ostype      CDATA           #IMPLIED
                devicetype  CDATA           #IMPLIED
                servicefp   CDATA           #IMPLIED
    >
    '''

    ATTRIBUTES = ['name','conf','extrainfo','method','version','product',
        'tunnel','proto','rpcnum','hostname','ostype','devicetype',
        'servicefp']

    DICT_ATTRS = ATTRIBUTES + ['name_slug', 'product_slug', 'ostype_slug', 
        'version_tag_slug', 'product_tag_slug', 'ostype_tag_slug',
        'devicetype_tag_slug']

    def __init__(self, name:str, conf:str=None, extrainfo:str=None,
            method:str=None, version:str=None, product:str=None,
            tunnel:str=None, proto:str=None, rpcnum:str=None,
            hostname:str=None, ostype:str=None, devicetype:str=None,
            servicefp=None):

        self._name = name
        self._tunnel = tunnel
        self.conf = conf
        self.extrainfo = extrainfo
        self.method = method
        self.version = version
        self.product = product
        self.proto = proto
        self.rpcnum = rpcnum
        self.hostname = hostname
        self.ostype = ostype
        self.devicetype = devicetype
        self.servicefp = servicefp

    @property
    @slugified()
    def name_slug(self):
        return self.name

    @property
    @slugified()
    def product_slug(self):
        return self.product

    @property
    @slugified()
    def ostype_slug(self):
        return self.ostype

    @property
    @slugified(slugify_kwargs=SLUGIFY_DEFAULTS_TAG)
    def version_tag_slug(self):
        return self.version

    @property
    @slugified(slugify_kwargs=SLUGIFY_DEFAULTS_TAG)
    def product_tag_slug(self):
        return self.product

    @property
    @slugified(slugify_kwargs=SLUGIFY_DEFAULTS_TAG)
    def ostype_tag_slug(self):
        return self.ostype

    @property
    @slugified(slugify_kwargs=SLUGIFY_DEFAULTS_TAG)
    def devicetype_tag_slug(self):
        return self.devicetype

    @property
    def tunnel(self):
        return self._tunnel

    @tunnel.setter
    def tunnel(self, value:str):
        self._tunnel = value
        if self._tunnel and self.name == 'http':
            self._name = 'https'

    @property
    def name(self):
        if self._name == 'http' and self.tunnel:
            self._name = 'https'
        return self._name

    @name.setter
    def name(self, value:str):
        if value == 'http' and self.tunnel:
            self._name = 'https'
        else:
            self._name = value

    def __eq__(self,val):
        if self.name == val: return True
        else: return False

    def to_row(self):
        row = []
        if self.name: row.append(self.name)
        if self.product: row.append(self.product)
        if self.version: row.append(self.version)
        if self.extrainfo: row.append(self.extrainfo)
        return row

class Port:
    '''A basic class representing an Nmap port object.

    nmap.dtd specification:

    <!ELEMENT port	(state , owner? , service?, script*) >
    <!ATTLIST port
			protocol	%port_protocols;    #REQUIRED
			portid		%attr_numeric;	    #REQUIRED
    >
    '''

    ATTRIBUTES = ['number','state','protocol','service','scripts',
        'portid']

    def __init__(self, number:int, state:str, protocol:str ,
            service:str=None, scripts:list=None,
            reason:str=None, *args, **kwargs):

        if scripts is None:
            scripts = list()

        if number.__class__ != int:
            try:
                number = int(number)
            except Exception as e:
                raise TypeError(
                    'Port number must be a string value that can be '
                    'converted to an integer when an int object is not '
                    'provided. Got {}. ({})'
                    .format(number, str(e))
                )

        self.number = number
        self.state = state
        self.reason = reason

        # ================================================================
        # BUG: Appears protocol can come through with all caps on occasion
        # ================================================================

        self.protocol = protocol.lower() if protocol else protocol

        if isinstance(service, str):
            self.service = Service(name = service)
        else:
            self.service = service

        self.scripts = scripts
        self.portid = self.number

    def __repr__(self,cls='Port'):

        return f'< [{cls}] Number: {self.number} ' \
            f'Protocol: \'{self.protocol}\' >'

    def __lt__(self, port):
        return self.number < port.number

    @property
    def __dict__(self):

        output = { a:getattr(self, a) for a in self.ATTRIBUTES }
        service = output.get('service')
        if service and isinstance(service, Service):
            output['service'] = service.__dict__

        scripts = output.get('scripts')
        if scripts and isinstance(scripts, list):
            output['scripts'] = [
                s.__dict__ for s in scripts
            ]

        return output

class PortDict(dict):
    '''A dictionary of port number to port list mappings that
    enforces a particular type of protocol.
    '''

    VALID_PROTOCOLS = ['tcp','udp','sctp','ip','icmp']

    def __init__(self, protocol):
        '''Initialize a PortDict object. Protocol determines the
        protocol associated with the port list.
        '''

        # Restrict protocols to valid values
        if not protocol in PortDict.VALID_PROTOCOLS:
            raise TypeError(
                f'Invalid protocol provided. Valid protocols: {PortDict.VALID_PROTOCOLS}'
            )
        
        self.protocol = protocol

    def __reduce__(self):

        # https://docs.python.org/3/library/pickle.html#object.__reduce__
        return (
            self.__class__,
            (self.protocol,),
            None,
            None,
            iter(self.items())
        )

    def __setitem__(self, key, value):
        '''Override __setitem__ to assure the key is an integervalue.
        '''
        # assure that the port is of type Port
        if not Port in value.__class__.__mro__ and not isinstance(value, dict):
            raise TypeError(
                'value argument must be of type Port'
            )

        # assure that the protocol associated with the port
        # matches the one of the dictionary
        if Port in value.__class__.__mro__:
            if value.protocol != self.protocol:
                raise ValueError(
                    'value protocol must match the PortDict protocol. '
                    'PortDict protocol is {}, value protocol was {}'.format(
                        self.protocol,
                        value.protocol)
                )
        
        key = int(key)
        super().__setitem__(key,value)

    @vp
    def append_port(self,port):

        self.__setitem__(port.number,port)

    def get(self,attr,value,regexp=False,value_attr=None):

        return PortList(self.values()).get(
            attr,value,regexp=regexp,value_attr=value_attr
        )

    @property
    def __dict__(self):

        return [p.__dict__ for p in self.values()]

class PortList(list):
    '''A superclass of list that performs type enforcement on objects
    as they're added while also providing a basic querying interface.
    '''

    @vp
    def __setitem__(self,key,value,*args,**kwargs):
        '''Override __setitem__ to enforce type.
        '''

        super().__setitem__(key,value,*args,**kwargs)

    @vp
    def append(self,value,*args,**kwargs):
        '''Override append enforce type.
        '''

        super().append(value)

    def get(self, attr, value, regexp=False, value_attr=None):
        '''Get ports from the list where the attribute value matches that of
        port objects in the list. Returns a port list, facilitating additional
        queries on the ports returned from the previous.
        '''

        if attr not in Port.ATTRIBUTES:
            raise TypeError(
                f'attr must be a PortObject attribute {Port.ATTRIBUTES}'
            )
        if not regexp:
            return PortList([p for p in self if p.__getattribute__(attr) == value])
        else:
            # TODO: Finish negotiation of attribute of attr object
            # for a service, should be `name`
            if value_attr:

                ports = PortList()
                for port in self:

                    attr_value = port.__getattribute__(attr) \
                        .__getattribute__(value_attr)

                    if not attr_value or not search(
                            value,attr_value):
                        continue

                    ports.append(port)

            else:

                ports = PortList([p for p in self if
                    search(value,p.__getattribute__(attr))]
                )

            return ports

def is_portdict(f):

    @wraps(f)
    def wrapper(self, ports):

        if ports is None:

            ports = PortDict(protocol=f.__name__.split('_')[0])

        elif not isinstance(ports, PortDict):

            raise TypeError(
                'ports must be of type PortDict, not {}'
                .format(type(ports)))

        return f(self, ports)

    return wrapper

class Host:
    '''Produces objects that resemble an Nmap host.
    '''

    PORT_PROTOCOLS = [
        'tcp',
        'udp',
        'ip',
        'sctp',
    ]

    def __eq__(self, value):

        if id(self) == id(value) or value in self.ip_addresses or (
            value in self.hostnames):
            return True
        else:
            return False

    def __init__(self, tcp_ports:PortDict=None, udp_ports:PortDict=None,
            ip_ports:PortDict=None, sctp_ports:PortDict=None,
            ipv4_address:str=None, ipv6_address:str=None,
            hostnames:list=None, status:str=None, status_reason:str=None,
            mac_address:str=None, ports:PortList=None):

        self.hostnames = list() if hostnames is None else hostnames
        self.ports = PortList() if ports is None else ports
        self.ip_addresses = list()

        # Technically protocols: https://nmap.org/book/scan-methods-ip-protocol-scan.htm
        # Nmap refers to them as ports though, so let's stick with that
        self.tcp_ports  = tcp_ports
        self.udp_ports  = udp_ports
        self.ip_ports   = ip_ports
        self.sctp_ports = sctp_ports

        self.parsed_mac  = None
        self.parsed_ipv4 = None
        self.parsed_ipv6 = None

        # IP/MAC Addresses
        self.mac_address  = mac_address
        self.ipv4_address = ipv4_address
        self.ipv6_address = ipv6_address

        # host/status 
        self.status = status

        # host/stats[@reason]
        self.status_reason = status_reason

    @property
    def ports(self):
        return self._ports

    @ports.setter
    def ports(self, ports):

        if not isinstance(ports, PortList):
            raise TypeError(
                'ports must be of type PortList')

        self._ports = ports

    @property
    def mac_address(self):

        if not hasattr(self, '_mac_address'):
            self._mac_address = None

        return self._mac_address

    @mac_address.setter
    def mac_address(self, mac):

        if hasattr(self, '_mac_address') and \
                mac == self._mac_address:
            return

        self._mac_address = mac

        if self._mac_address is not None:
            self.parsed_mac = MAC(mac)

    @property
    def ipv4_address(self):
        return self._ipv4_address

    @ipv4_address.setter
    def ipv4_address(self, addr):

        if hasattr(self, '_ipv4_address'):

            if self._ipv4_address == addr:
                return
    
            elif self._ipv4_address is not None and \
                    self.ipv4_address in self.ip_addresses:
    
                del(self.ip_addresses[
                    self.ip_addresses.index(self.ip_address)])

        self._ipv4_address = addr

        if self._ipv4_address is not None:
            self.parsed_ipv4 = IPAddress(addr)

    @property
    def ipv6_address(self):
        return self._ipv6_address

    @ipv6_address.setter
    def ipv6_address(self, addr):

        if hasattr(self, '_ipv6_address'):

            if self._ipv6_address == addr:
                return
    
            elif self._ipv6_address is not None and \
                    self.ipv6_address in self.ip_addresses:
    
                del(self.ip_addresses[
                    self.ip_addresses.index(self.ip_address)])

        self._ipv6_address = addr

        if self.ipv6_address is not None:
            self.parsed_ipv6 = IPAddress(addr)

    @property
    def tcp_ports(self):
        return self._tcp_ports

    @tcp_ports.setter
    @is_portdict
    def tcp_ports(self, ports):
        self._tcp_ports = ports

    @property
    def udp_ports(self):
        return self._udp_ports

    @udp_ports.setter
    @is_portdict
    def udp_ports(self, ports):
        self._udp_ports = ports

    @property
    def ip_ports(self):
        return self._ip_ports

    @ip_ports.setter
    @is_portdict
    def ip_ports(self, ports):
        self._ip_ports = ports

    @property
    def sctp_ports(self):
        return self._sctp_ports

    @sctp_ports.setter
    @is_portdict
    def sctp_ports(self, ports):
        self._sctp_ports = ports

    @vp
    def append_port(self, port):
        '''Pass a port to the Host and allow it to add it to the
        appropriate PortList according to the protocol.
        '''

        if not port.protocol in self.PORT_PROTOCOLS:
            raise InvalidProtocolError(
                'Unsupported protocol provided while appending port to host: ' + \
                port.protocol
            )

        self.__getattribute__(port.protocol+'_ports').append_port(port)
        self.ports.append(port)

    @property
    @slugified()
    def ipv6_address_slug(self):
        return self.ipv6_address

    @property
    @slugified()
    def mac_address_slug(self):
        return self.mac_address

    @property
    def __dict__(self):

        return dict(
            ipv4_address = self.ipv4_address,
            ipv6_address = self.ipv6_address,
            hostnames = self.hostnames,
            status = self.status,
            status_reason = self.status_reason,
            mac_address = self.mac_address,
            tcp_ports = self.tcp_ports.__dict__,
            udp_ports = self.udp_ports.__dict__,
            ip_ports = self.ip_ports.__dict__,
            sctp_ports = self.sctp_ports.__dict__)

    def get_ports(self, *args, **kwargs):
        return [port.number for port in self.ports]

    def to_services(self, *args, **kwargs):

        return [[f'{self.ipv4_address}:{port.number}',port.protocol]+port.service.to_row() for port in self.ports if port.service.product]


    def to_ports(self, service_search=[], sreg=False,
            *args, **kwargs):
        '''Translate the host to a list of port numbers.
        '''

        if not service_search:
            return self.get_ports()
        
        ports = PortList()
        for service in service_search:

            # ===================
            # HANDLE REGEX SEARCH
            # ===================

            if sreg:

                ports += self.ports.get(attr='service',value=service,
                    regexp=True,value_attr='name')
                ports += self.ports.get(attr='service',value=service,
                    regexp=True,value_attr='extrainfo')

            # ===================
            # HANDLE MATCH SEARCH
            # ===================

            else:

                ports += self.ports.get(attr='service',value=service)
                ports += self.ports.get('service',value=service,
                        value_attr='extrainfo')

        return [str(p.number) for p in set(ports)]


    def get_addresses(self,fqdns=False, port_search=[], service_search=[],
            sreg=False, port_required=False, *args, **kwargs):

        port_search = [int(p) for p in port_search]

        # ====================
        # REQUIRE AN OPEN PORT
        # ====================

        if port_required and not self.ports.get('state','open'):
            return []

        # =======================
        # SEARCH FOR PORT NUMBERS
        # =======================

        for port in port_search:
            if not self.ports.get('number',port).get('state','open'):
                return []

        # ===============
        # SEARCH SERVICES
        # ===============

        if service_search:
            matched = False
            for service in service_search:

                # ===================
                # HANDLE REGEX SEARCH
                # ===================

                if sreg:

                    if self.ports.get(attr='service',value=service,
                        regexp=True,value_attr='name'):
                        matched = True
                        break
                    
                    if self.ports.get(attr='service',value=service,
                        regexp=True,value_attr='extrainfo'):
                        matched = True
                        break

                # ===================
                # HANDLE MATCH SEARCH
                # ===================

                else:

                    if self.ports.get(attr='service',value=service):
                        matched = True
                        break

                    if self.ports.get('service',value=service,
                            value_attr='extrainfo'):
                        matched = True
                        break
                    
            if not matched: return []

        # ================================
        # EXTRACT HOSTNAMES WHEN REQUESTED
        # ================================

        addresses = []
        if fqdns:
            addresses += self.hostnames

        # ================
        # GET IP ADDRESSES
        # ================
        # TODO: add option for ipv4/6/fqdn option

        if self.ipv4_address:
            addresses.append(self.ipv4_address)
        elif self.ipv6_address:
            addresses.append(self.ipv6_address)

        # Assure host has at least one address
        if not addresses:
            raise Exception(
                'Host has no address'
            )

        return sorted(addresses)


    def to_addresses(self,*args,**kwargs):
        return self.get_addresses(*args,**kwargs)

    def to_san_dns_names(self,fqdns=False,open_only=True,protocols=['tcp'],
            scheme_layer=None,mangle_functions=[],port_search=[],
            service_search=[],sreg=None,*args,**kwargs):

        output = []
        for transport_protocol in protocols:
            for port_number,port in self \
                    .__getattribute__(transport_protocol+'_ports') \
                    .items():
                        for script in port.scripts:
                            output += [s.strip() for s
                                    in script.san_dns_names]

        return output

    def to_hostports(self, protocols=['tcp'], fqdns=False,
            *args, **kwargs):
        '''Return a list of transport-layer URI values with each open port
        suffixed instead of only a single value.
        '''

        addresses = self.get_addresses()
        output = []

        for transport_protocol in protocols:

            ports = []
    
            for port_number, port in getattr(self,
                    transport_protocol+'_ports') \
                    .items():

                if not port.state == 'open': continue
                ports.append(str(port_number))

            for address in addresses:

                output.append(
                    f'{transport_protocol}://{address}:{",".join(ports)}'
                )

        return sorted(output)


    def to_sockets(self,fqdns=False,open_only=True,protocols=['tcp'],
            scheme_layer=None,mangle_functions=[],port_search=[],
            service_search=[],sreg=None,extrainfo=False,*args,**kwargs):
        """
        Return a list of socket values derived from service objects
        associated with a given host.

        fqdns - boolean - Determine if fqdns should be returned
        open_only - return only open port
        protocols - list - list of valid protocols
        scheme_layer - string - application or transport layer
        mangle_functions - a list of functions which the string
        final address will be passed to. Useful for mangling services
        to specific values.
        """

        # =============
        # ENFORCE TYPES
        # =============

        # Assure protocols is a list
        if protocols.__class__ != list:
            raise TypeError(
                'protocols must be a list'
            )

        # Assure valid scheme type is supplied
        if scheme_layer:
            if not scheme_layer in ['transport','application']:
                raise ValueError(
                    'scheme_layer must be either transport or application'
                )

        addresses = self.get_addresses(fqdns=fqdns)
        output = []

        for transport_protocol in protocols:
            for port_number,port in self \
                .__getattribute__(transport_protocol+'_ports') \
                .items():

                # =================
                # ENFORCE OPEN ONLY
                # =================

                if open_only and port.state != 'open': continue

                # ==============
                # DO PORT SEARCH
                # ==============

                if port_search and not port.number in port_search:
                    continue

                # =================
                # DO SERVICE SEARCH
                # =================

                if service_search:

                    # ===============
                    # DO MATCH SEARCH
                    # ===============

                    if not sreg and \
                        (not port.service or \
                        not port.service.name in service_search):
                            continue

                    # ===============
                    # DO REGEX SEARCH
                    # ===============

                    else:

                        matched = False
                        for ser in service_search:

                            if search(ser,port.service.name):
                                matched=True
                                break

                            if port.service.extrainfo and \
                                    search(ser,port.service.extrainfo):
                                matched=True
                                break

                        if not matched: continue

                # =======================
                # BUILD THE SCHEME PREFIX
                # =======================

                if scheme_layer == 'transport':
                    if port.service.tunnel in ['ssl','tls']:
                        scheme = port.service.tunnel+'/'+transport_protocol+'://'
                    else:
                        scheme = transport_protocol+'://'
                elif scheme_layer == 'application' and port.service:
                    if port.service.name == 'http' and port.service.tunnel in ['ssl','tls']:
                        scheme = port.service.name+'s://'
                    else:
                        scheme = port.service.name+'://'
                else:
                    scheme = ''
                
                # ====================
                # FORMAT THE ADDRESSES
                # ====================

                for address in addresses:

                    # Format the address
                    addr = f'{scheme}{address}:{port.number}'

                    # Add extrainfo when requested
                    if extrainfo:

                        info = []
                        if port.service.product:
                            info.append(f'Product:::' \
                                    f'{port.service.product}')

                        if port.service.extrainfo:
                            info.append(f'ExtraInfo:::'\
                                    f'{port.service.extrainfo}')

                        if port.service.version:
                            info.append(f'Version:::' \
                                    f'{port.service.version}')

                        addr += ","+"; ".join(info)

                    for func in mangle_functions:
                        addr = func(addr)

                    output.append(addr)

        return sorted(output)

    def to_uris(self,*args,**kwargs):
        """Return a list of URIs derived from the sockets associated
        with a given host.
        """

        return self.to_sockets(*args,**kwargs)

class FromXML:

    @staticmethod
    @ve
    def host(ehost):
        
        status = ehost.find('status').get('state')
        status_reason = ehost.find('status').get('reason')
        
        # Getting addresses
        addresses = {}
        for eaddress in ehost.findall('.//address'):
            addr_type = eaddress.get('addrtype')
            addresses[addr_type+'_address'] = eaddress.get('addr')
        
        # Getting ehostnames
        hostnames = [
            hn.attrib['name'] for hn in ehost.findall('.//hostname')
        ]
        
        # Create a ehost object
        return Host(**addresses,
            hostnames=hostnames,
            status=status,
            status_reason=status_reason)

    @staticmethod
    @ve
    def port(eport):
        
        # Get port information
        portid = eport.get('portid')
        protocol = eport.get('protocol')

        # Handle state element
        estate = eport.find('.//state')
        state = estate.get('state')
        reason = estate.get('reason')

        # Handle the service element
        service = eport.find('./service')
        if service != None:
            service = FromXML.service(service)

        # Build and return the port
        return Port(number=portid,
            state=state,
            reason=reason,
            protocol=protocol,
            service=service)

    @staticmethod
    @ve
    def service(eservice):
        es = eservice

        # Use the attribute list to build the arguments for Service
        attrs = {}
        for attr in Service.ATTRIBUTES:
            attrs[attr] = es.get(attr)

        # Return a new service object
        return Service(**attrs)

GNMAP_HOST_RE = \
    compile('Host: (?P<host>.+) \((?P<hostname>.+)' \
        '?\)\s+Status:\s+(?P<status>.+)')
GNMAP_PORTS_RE = compile('(?P<port>[0-9]{1,5})/(?P<status>[a-z]' \
    '{1,})/{1,}(?P<protocol>([a-z]|-)+)/')

class FromGNMAP:
    '''DRAGONS BE HERE

    This code hasn't been tested at all. Was developing it before
    descovering XSL transforms that made it significantly more
    efficient to remove unwanted content from large XML files
    '''

    @staticmethod
    def hostField(line):

        matches = findall(GNMAP_HOST_RE, line)

        if not matches:
            raise ValueError(
                f'Invalid host line provided: {line}'
            )

        address, hostname, status = matches[0]
        address = IPAddress(address)
        
        kwargs={
            f'ipv{address.version}_address':address,
            'status':status.lower(),
            'status-reason':'gnmap-unknown',
        }

        if hostname: kwargs['hostname'] = hostname.lower()

        return Host(**kwargs)

    @staticmethod
    def iterPortFields(line,only_open=True):
        
        matches = findall(GNMAP_PORTS_RE, line)

        if not matches:
            raise ValueError(
                f'Invalid port line provided: {line}'
            )

        for match in matches:
            port, state, protocol = match[0:3]
            if only_open and state != 'open': continue
            port=Port(
                    number=port, state=state,
                    protocol=protocol, service='gnmap-unknown',
                    reason='gnmap-unknown'
                )
            yield port


