#!/usr/bin/env python3

from re import search
from sys import exit

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

class Script:
    '''A basic representation of an Nmap script.

    nmap.dtd specification:

    <!ELEMENT script	(#PCDATA|table|elem)* >
    <!ATTLIST script	
	id	CDATA	#REQUIRED
	output	CDATA	#REQUIRED
    >
    '''

    def __init__(self,id,output):

        self.id = id
        self.output = output

class Service:
    '''A basic representation of an Nmap service.

    nmap.dtd specification:

    <!ELEMENT service	(cpe*) >
    <!ATTLIST service
    			name		CDATA		#REQUIRED
    			conf		%service_confs;	#REQUIRED
                        method          (table|probed)  #REQUIRED
                        version         CDATA           #IMPLIED
                        product         CDATA           #IMPLIED
                        extrainfo       CDATA           #IMPLIED
    			tunnel		(ssl)		#IMPLIED
    			proto		(rpc)		#IMPLIED
    			rpcnum		%attr_numeric;	#IMPLIED
    			lowver		%attr_numeric;	#IMPLIED
    			highver		%attr_numeric;	#IMPLIED
                        hostname        CDATA           #IMPLIED
                        ostype          CDATA           #IMPLIED
                        devicetype      CDATA           #IMPLIED
                        servicefp       CDATA           #IMPLIED
    >
    '''

    ATTRIBUTES = ['name','conf','method','version','product',
        'tunnel','proto','rpcnum','hostname','ostype','deviceytpe']

    def __init__(self,name,conf=None,method=None,version=None,
        product=None,tunnel=None,proto=None,rpcnum=None,hostname=None,
        ostype=None,devicetype=None):

        self.name = name
        self.conf = conf
        self.method = method
        self.version = version
        self.product = product
        self.tunnel = tunnel
        self.proto = proto
        self.rpcnum = rpcnum
        self.hostname = hostname
        self.ostype = ostype
        self.devicetype = devicetype

    def __eq__(self,val):
        if self.name == val: return True
        else: return False

class Port:
    '''A basic class representing an Nmap port object.

    nmap.dtd specification:

    <!ELEMENT port	(state , owner? , service?, script*) >
    <!ATTLIST port
			protocol	%port_protocols;    #REQUIRED
			portid		%attr_numeric;	    #REQUIRED
    >
    '''

    ATTRIBUTES = ['number','state','protocol','service','script',
        'port_id']

    def __init__(self,number,state,protocol,service=None,scripts=[],
            reason=None, *args, **kwargs):

        self.number = number
        self.state = state
        self.reason = reason
        self.protocol = protocol
        self.service = service
        self.scripts = scripts
        self.portid = self.number

    def __repr__(self,cls='Port'):

        return f'< [{cls}] Number: {self.number} ' \
            f'Protocol: \'{self.protocol}\' >'

class PortDict(dict):
    '''A dictionary of port number to port list mappings that
    enforces a particular type of protocol.
    '''

    VALID_PROTOCOLS = ['tcp','udp','sctp','ip','icmp']

    def __init__(self,protocol):
        '''Initialize a PortDict object. Protocol determines the
        protocol associated with the port list.
        '''

        # Restrict protocols to valid values
        if not protocol in PortDict.VALID_PROTOCOLS:
            raise TypeError(
                f'Invalid protocol provided. Valid protocols: {PortDict.VALID_PROTOCOLS}'
            )
        
        self.protocol = protocol

    def __setitem__(self,key,value):
        '''Override __setitem__ to assure the key is an integervalue.
        '''
        # assure that the port is of type Port
        if not Port in value.__class__.__mro__:
            raise TypeError(
                'value argument must be of type Port'
            )

        # assure that the protocol associated with the port
        # matches the one of the dictionary
        if value.protocol != self.protocol:
            raise ValueError(
                'value protocol must match the PortDict protocol'
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

    def get(self,attr,value,regexp=False,value_attr=None):
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
                return PortList([p for p in self if search(
                    value,p.__getattribute__(attr) \
                        .__getattribute__(value_attr)
                    )]
                )
            else:
                return PortList([p for p in self if
                    search(value,p.__getattribute__(attr))]
                )

class Host:
    '''Produces objects that resemble an Nmap host.
    '''

    def __init__(self,tcp_ports=None,udp_ports=None,ip_ports=None,
            sctp_ports=None,ipv4_address=None,ipv6_address=None,
            hostnames=[],status=None,status_reason=None,
            mac_address=None,ports=None):

        # Assure ports are provided in as PortLists
        for k,v in {k:v for k,v in locals().items()
                if k != 'ports' and k.endswith('ports')}.items():
            if v and v.__class__ != PortDict:
                raise TypeError('Port arguments must be of type PortDict')

        self.tcp_ports = tcp_ports
        self.udp_ports = udp_ports
        
        # Technically protocols: https://nmap.org/book/scan-methods-ip-protocol-scan.htm
        # Nmap refers to them as ports though, so let's stick with that
        self.ip_ports = ip_ports

        self.sctp_ports = sctp_ports
        self.ipv6_address = ipv6_address
        self.ipv4_address = ipv4_address

        # Each hostname is in a hostname element, a child of the 
        # hostnames element for a host
        self.hostnames = hostnames

        # host/status 
        self.status = status

        # host/stats[@reason]
        self.status_reason = status_reason
        self.mac_address = mac_address

        # Initialize a portlist
        if not ports:
            self.ports = PortList()

        # Set provided ports list
        else:

            # Assure the ports object is of type PortList
            if port and ports.__class__ != PortList:
                raise TypeError(
                    'ports value must be of type PortList'
                )
            self.ports = ports

        # Assure all ports are a portdict unless added to the portlist
        for attr,value in self.__dict__.items():
            if not value and attr.endswith('_ports'):
                self.__setattr__(attr,PortDict(protocol=attr.split('_')[0]))

    @vp
    def append_port(self,port):
        '''Pass a port to the Host and allow it to add it to the
        appropriate PortList according to the protocol.
        '''

        self.__getattribute__(port.protocol+'_ports').append_port(port)
        self.ports.append(port)

    def get_ports(self, *args, **kwargs):
        return [port.number for port in self.ports]

    def to_ports(self, *args, **kwargs):
        return self.get_ports()

    def get_addresses(self,fqdns=False, port_search=[], service_search=[],
            sreg=False, port_required=False, *args, **kwargs):

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

                # ===================
                # HANDLE MATCH SEARCH
                # ===================

                else:

                    if self.ports.get('service',service):
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

    def to_sockets(self,fqdns=False,open_only=True,protocols=['tcp'],
            scheme_layer=None,mangle_functions=[],port_search=[],
            service_search=[],sreg=None,*args,**kwargs):
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

                        if not matched: continue

                # =======================
                # BUILD THE SCHEME PREFIX
                # =======================

                if scheme_layer == 'transport':
                    scheme = transport_protocol+'://'
                elif scheme_layer == 'application' and port.service:
                    scheme = port.service.name+'://'
                else:
                    scheme = ''
                
                # ====================
                # FORMAT THE ADDRESSES
                # ====================

                for address in addresses:
                    addr = f'{scheme}{address}:{port.number}'
                    for func in mangle_functions:
                        addr = func(addr)
                    output.append(addr)

        return sorted(output)

    def to_uris(self,*args,**kwargs):
        """Return a list of URIs derived from the sockets associated
        with a given host.
        """

        return self.to_sockets(*args,**kwargs)
