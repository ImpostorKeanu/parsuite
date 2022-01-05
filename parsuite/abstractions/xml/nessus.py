from parsuite.abstractions.xml.generic import network_host as NH
from parsuite.abstractions.xml.generic.network_host import Host, PortDict, PortList
from parsuite.abstractions.xml.generic.exceptions import *
from parsuite import decorators
import re

plugin_name_re = pname_re = re.compile('(\s|\W)+')
ipv4_re = i4_re = re.compile('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
ipv6_re = i6_re = re.compile('^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$')
fqdn_re = re.compile('[a-z]', re.I)

ve = decorators.validate_lxml_module

class FromXML:

    @staticmethod
    @ve
    def plugin_ids(tree) -> list:
        '''Return a list of pluginID Elements.

        Args:
            tree: lxml.etree object.
        '''

        return tree.xpath('.//@pluginID')

    # TODO: Make a generator version of this function
    @staticmethod
    @ve
    def all_report_hostnames(tree) -> dict:
        '''Return a dictionary of string hostnames organized by 
        string IP address.

        Args:
            tree: lxml.etree.ElementTree object.

        Notes:
            - This is a slow function. It iterates over all ReportHost
              elements in an effort to identify targets with the same
              IP address.
        '''

        out = {}

        for rh in tree.xpath('//ReportHost'):

            ip, hostnames = FromXML.report_host_hostnames(rh)
            out[ip] = hostnames

            rdns = rh.xpath('./tag[@name="rdns"]')
            fqdn = rh.xpath('./tag[@name="fqdn"]')

            rdns = rdns.text if rdns else None
            fqdn = fqdn.text if fqdn else None

            if rdns and rdns not in out[ip]:
                out[ip].append(rdns)

            if fqdn and fqdn not in out[ip]:
                out[ip].append(fqdn)

        return out

    @staticmethod
    @ve
    def report_host_hostnames(ereport_host) -> (str, list,):
        '''Return the str IP address and a list of str hostnames for
        an XML ReportHost element.

        Args:
            tree: lxml.etree.Element object.

        Returns:
            (str ip address, [str hostnames])

        Notes:
            - This function calls FromXML.all_report_hostnames, thus it's
            quite slow.
        '''

        host_ip = ereport_host \
            .xpath('./HostProperties/tag[@name="host-ip"]')[0] \
            .text

        hostnames = []

        for rh in ereport_host.xpath(
                '..//ReportHost/HostProperties/tag'
                '[@name="host-ip" and '
                f'text()="{host_ip}"]/../..'):

            name = rh.get('name')

            if fqdn_re.search(name):
                hostnames.append(name)

        return host_ip, hostnames

    @staticmethod
    @ve
    def report_host(ereport_host, all_hostnames=True):
        '''Generate and return a ReportHost object from an XML element
        object generated by xml.etree.ElementTree.'''

        ele = ereport_host

        kwargs = {'name':ele.get('name')}

        for attr in ReportHost.HOST_PROPERTY_ATTRIBUTES:

            for iele in ele.findall(f'./HostProperties//tag[@name="{attr}"]'):
                try:
                    kwargs[attr.replace('-','_').replace('host_','')] = iele.text
                except:
                    kwargs[attr] = None

        if all_hostnames:
            ip, kwargs['hostnames'] = FromXML.report_host_hostnames(
                    ereport_host)

        return ReportHost(**kwargs)

    @staticmethod
    @ve
    def report_item(ereport_item):
        '''Initialize and return a ReportItem object from an XML
        element object generated by xml.etree.
        '''

        ri = ereport_item
        raw = {}

        # Extract attribute values from the ReportItem element
        for attr in ReportItem.ATTRIBUTES:
            text = ri.get(attr)
            attr = RI.na(attr)
            raw[attr]=text

        # Extract text from relevant child tag elements
        for tag in ReportItem.CHILD_TAGS:
            try:
                text = ri.find(f'{tag}').text
            except:
                text = None

            tag = RI.na(tag)
            raw[tag] = text

        raw['metasploit_modules'] = [
            ele.text for ele in ri.findall('.//metasploit_name')
        ]

        # Initialize and return a ReportItem object
        return ReportItem(**raw)

class Plugin:
    '''Represents a Nessus plugin. The name associate with a ReportItem
    and id will be bound to these objects. Facilitates easy lookups between
    ReportItems and PluginOutputDicts, the latter of which is an attribute
    of Port port objects.
    '''

    def __init__(self,name,id):

        self.name = name
        self.id = id

    def __eq__(self,value):

        if value == self.name or value == self.id:
            return True
        else:
            return False

class PluginOutputDict(dict):
    
    def append_output(self,plugin_id,output):

        if plugin_id in self:
            self[plugin_id].append(output)
        else:
            self[plugin_id] = [output]

class Port(NH.Port):
    '''Override the generic NetworkHost.Port object with one that
    has a `report_items` attribute used to track ReportItem
    output for a given port.
    '''
    
    def __init__(self, plugin_outputs = PluginOutputDict(),
        *args, **kwargs):
        '''report_items is a dictionary of {plugin_id:plugin_output}.
        '''

        # initialize a list of report items
        self.plugin_outputs = plugin_outputs

        # call the parent constructor
        super().__init__(*args,**kwargs)


class ReportHost(NH.Host):

    HOST_PROPERTY_ATTRIBUTES = ['mac-address','operating-system',
       'netbios-name','host-fqdn','host-rdns','host-ip']

    PORT_PROTOCOLS = NH.Host.PORT_PROTOCOLS+['icmp']

    def __init__(self,name,operating_system=None,mac_address=None,
        netbios_name=None,rdns=None,ip=None,fqdn=None,
        hostnames=None, ports=NH.PortList(),
        icmp_ports=NH.PortDict('icmp')):

        # =====================
        # INITIALIZE ATTRIBUTES
        # =====================

        self.name = name
        self.operating_system = operating_system
        self.mac_address = mac_address
        self.netbios_name = netbios_name
        self.rdns = rdns
        self.ip = ip
        self.icmp_ports=icmp_ports

        # ============================
        # INITIALIZE PARENT ATTRIBUTES
        # ============================
        
        kwargs = {}
        kwargs['status_reason'] = 'nessus-up'

        # TODO: Likely bug here.
        if re.match(ipv4_re, ip):
            kwargs['ipv4_address']=ip
        elif re.match(ipv6_re, ip):
            kwargs['ipv4_address']=ip

        hostnames = hostnames if hostnames else []
        if fqdn: hostnames.append(fqdn)
        if rdns and rdns != ip: hostnames.append(rdns)
        kwargs['hostnames'] = hostnames
        
        super().__init__(ports=ports,**kwargs)

class ReportItem:
    '''A simple object representing a ReportItem element from a 
    Nessus XML file.

    _Note_: This object varies in terms of report output. The
    Nessus XML document will associate a report item detailing
    all aspects of a given vulnerabiltity for each host, including
    details about the finding: description, plugin name, type, etc.
    This is highly inefficient in terms of memory usage, so _output
    from the plugin is not stored with a report item_. Output for
    a given report item is associated with a Port object in the
    form of `Port.report_items['plugin_id'] = ['outputs']

    '''

    # Nessus XML ReportItem attributes to track
    ATTRIBUTES = ['port','svc_name', 'protocol', 'severity','pluginID',
        'pluginName', 'pluginFamily']

    # Nessus child elements to track (text content)
    CHILD_TAGS = ['agent','always_run','description','fname',
        'plugin_modification_date', 'plugin_name', 'plugin_output',
        'plugin_publication_date', 'plugin_type', 'risk_factor',
        'script_copyright', 'script_version', 'solution',
        'synopsis', 'exploit_available',
        'exploit_framework_canvas', 'exploit_framework_metasploit',
        'exploit_framework_core', 'metasploit_name', 'canvas_package'
    ]

    # Normalize XML names that are invalid or undesirable for use as
    # a python object attribute.
    NORMALIZED_MAP = {
        'exploit_framework_canvas':'exploit_framework_canvas',
        'exploit_framework_metasploit':'exploit_framework_metasploit',
        'exploit_framework_core':'exploit_framework_core',
        'pluginID':'plugin_id','pluginName':'plugin_name',
        'pluginFamily':'plugin_family'
    }

    NORMALIZED = []
    for a in ATTRIBUTES+CHILD_TAGS:
        if a in NORMALIZED_MAP:
            NORMALIZED.append(NORMALIZED_MAP[a])
        else:
            NORMALIZED.append(a)

    
    def __init__(self, agent, always_run, description, fname,
            plugin_modification_date, plugin_name,
            plugin_publication_date, plugin_type, risk_factor,
            script_copyright, script_version, solution,
            synopsis, port, svc_name, protocol,
            severity, plugin_id, plugin_family, exploit_available,
            exploit_framework_canvas, exploit_framework_metasploit,
            exploit_framework_core, metasploit_name, canvas_package,
            plugin_output,metasploit_modules=[]):
        
        self.exploit_frameworks = []
        port_kwargs = {'number':port,'protocol':protocol,'state':'open'}
        self.port = Port(**port_kwargs)
        self.metasploit_modules = metasploit_modules
            
        
        for attr in (ReportItem.ATTRIBUTES+ReportItem.CHILD_TAGS):

            if attr == 'port': continue

            attr = RI.na(attr)
            val = locals()[attr]
            
            if attr.startswith('exploit_framework') and val:
                self.exploit_frameworks.append(attr.split('_')[-1])

            if attr == 'risk_factor':
                val = val.lower()

            if val == 'true': val = True
            elif val == 'false': val = False

            self.__setattr__(attr,val)

        self.exploitable = self.exploit_available

        # Determine if the report item is dealing with SSL/TLS
        for k in ['ssl','tls']:

            wrapped = False
            if self.plugin_name.find(k) > -1 or self.plugin_name.find(k.upper()) > -1:
                wrapped = True

            self.__setattr__(k,wrapped)


    @staticmethod
    def normalize_attr(attr):
        '''Map a given XML attribute name back to a value that has
        been normalized (suitable for use as a Python object attribute
        name).
        '''

        if attr in ReportItem.NORMALIZED_MAP:
            return ReportItem.NORMALIZED_MAP[attr]
        else:
            return attr

    # convenience is convenient
    na = normalize_attr
    
    def additional_info(self):

        output = f'# synopsis\n\n{str(self.__getattribute__("synopsis"))}'
        for k in ['solution','description', 'plugin_type']:

            output += f'\n\n# {k}\n\n{str(self.__getattribute__(k))}'

        if self.exploit_frameworks:

            frameworks = '\n'.join(self.exploit_frameworks)
            output += f'\n\n# exploit_frameworks:\n\n{frameworks}'

        if self.metasploit_modules:

            modules = '\n'.join(self.metasploit_modules)
            output += f'\n\n# msf_modules:\n\n{modules}'

        return output+'\n'

# convenience is convenient
RI = ReportItem
