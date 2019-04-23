#!/usr/bin/env python3

from re import search
from sys import exit

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

    def __init__(self,name,confs=None,method=None,version=None,
        product=None,tunnel=None,proto=None,rpcnum=None,hostname=None,
        ostype=None,devicetype=None):

        self.name = name
        self.confs = confs
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
            reason=None):

        self.number = number
        self.state = state
        self.reason = reason
        self.protocol = protocol
        self.service = service
        self.scripts = scripts
        self.portid = self.number

class PortDict(dict):
    '''A dictionary of protocol to PortList mappings
    '''

    VALID_PROTOCOLS = ['tcp','udp','sctp','ip']

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

        if value.__class__ != Port:
            raise TypeError(
                f'PortDict objects hold only Port objects, not {value.__class__}'
            )
        
        key = int(key)
        super().__setitem__(key,value)

    def append_port(self,port):
        
        if port.__class__ != Port:
            raise TypeError(
                f'PortDict objects hold only Port objects, not {value.__class__}'
            )

        self.__setitem__(port.number,port)  


class PortList(list):
    '''A superclass of list that performs type enforcement on objects
    as they're added while also providing a basic querying interface.
    '''

    def __setitem__(self,key,value,*args,**kwargs):
        '''Override __setitem__ to enforce type.
        '''

        if value.__class__ != Port:
            raise TypeError(
                'PortList values must be of type Port'
            )

        super().__setitem__(key,value,*args,**kwargs)

    def append(self,value,*args,**kwargs):
        '''Override append enforce type.
        '''

        if value.__class__ != Port:
            raise TypeError(
                'PortList values must be of type Port'
            )

        # Handle duplicate ports by removing the original and appending
        # the new one.
        known_port = self.get('protocol',value.protocol) \
            .get('number',value.number)
        if known_port: self.remove(known_port[0])

        # Append the port
        super().append(value,*args,**kwargs)

    def get(self,attr,value,regexp=False):
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
            return PortList([p for p in self if
                re.search(value,p.__getattribute__(attr))]
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
                if k.endswith('ports')}.items():
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

    def append_port(self,port):
        '''Pass a port to the Host and allow it to add it to the
        appropriate PortList according to the protocol.
        '''

        if port.__class__ != Port:
            raise TypeError(
                'port must be of type Port'
            )

        self.__getattribute__(port.protocol+'_ports').append_port(port)
        self.ports.append(port)

    def get_addresses(self,fqdns=False, port_search=[], service_search=[],
            sreg=False,*args, **kwargs):

        for port in port_search:
            if not self.ports.get('number',port).get('state','open'):
                return []

        if service_search:
            matched = False
            for service in service_search:

                if sreg:
                    if self.ports.get('service',service,True):
                        matched = True
                        break
                else:
                    if self.ports.get('service',service):
                        matched = True
                        break
                    
            if not matched: return []

        if fqdns:
            addresses = self.hostnames
        else:
            addresses = []

        if self.ipv4_address:
            addresses.append(self.ipv4_address)
        elif self.ipv4_address:
            addresses.append(self.ipv6_address)

        if not addresses:
            raise Exception(
                'Host has no address'
            )

        return addresses

    def to_addresses(self,*args,**kwargs):
        return self.get_addresses(*args,**kwargs)

    def to_sockets(self,fqdns=False,open_only=True,protocols=['tcp'],
            scheme_layer=None,mangle_functions=[],port_search=[],
            service_search=[],*args,**kwargs):
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

                if port_search and not port.number in port_search:
                    continue

                if service_search:
                    if not port.service: continue
                    if not port.service.name in service_search:

                        matched = False
                        for ser in service_search:
                            if re.search(ser,port.service.name):
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

        return output

    def to_uris(self,fqdns=False,protocols=['tcp'],open_only=True,
            scheme_layer='application',mangle_functions=[],
            port_search=[]):
        """Return a list of URIs derived from the sockets associated
        with a given host.
        """

        return self.to_sockets(fqdns=fqdns, protocols=protocols,
            open_only=open_only, scheme_layer=scheme_layer,
            mangle_functions=mangle_functions,port_search=port_search)
