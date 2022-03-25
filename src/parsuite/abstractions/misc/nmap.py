import re

service_re = re.compile('^(?P<name>(\w|\-|\.|:)+)\s+'\
    '(?P<port>[0-9]{1,5})/'\
    '(?P<protocol>(tcp|udp|sctp))\s+'\
    '(?P<frequency>[0-9]\.[0-9]+)')

class Service:

    def __init__(self,name,port,protocol,frequency):

        if not type(frequency) == float:
            raise TypeError('Frequency must be a float')

        self.name = name
        self.port = port
        self.protocol = protocol
        self.frequency = frequency

    def __repr__(self):

        return f'< [Service] name: {self.name} port: {self.port} '\
            f'protocol: {self.protocol} frequency: {self.frequency} >'

    def __lt__(self, val):
        '''Simple less-than method to facilitate sorting.
        '''

        classes = [Service,float]

        if not val.__class__ in classes:
            raise TypeError(
                'Service comparison must occur between a float or service'
            )

        if val.__class__ == Service: val = val.frequency

        if self.frequency < val:
            return True
        else:
            return False

    def __add__(self, val):
        '''Return the port number summed with val.
        '''

        if val.__class__ != int and val.__class__ != Service:
            raise ValueError(
                   'val must be either int or Service'
            )

        if val.__class__ == Service: val = val.port

        return self.port + val

    @staticmethod
    def from_line(line):
        '''Create a Service object from a line in the Nmap
        services file.
        '''
        line = line.strip()
    
        # create the namedtuple
        groups = re.match(service_re, line).groupdict()
        groups['frequency'] = float(groups['frequency'])
        groups['port'] = int(groups['port'])
    
        return Service(**groups)

def parse_top_ports(infile,name_search=[],protocols=[],*args, **kwargs):
    '''Parse the nmap top ports file.
    '''

    if name_search.__class__ != list:
        raise TypeError('name_search must be a list')

    services = {protocol:[] for protocol in protocols}

    # Parse the nmap-services file
    with open(infile) as service_file:

        for line in service_file:

            if not line or line[0] == '#': continue

            service = Service.from_line(line)

            if protocols and service.protocol not in protocols:
                continue

            if name_search:
                for search_val in name_search:
                    if re.search(re.escape(search_val),service.name):
                        services[service.protocol].append(service)
            else: services[service.protocol].append(service)

    return services

