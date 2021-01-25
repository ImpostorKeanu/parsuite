from django.db import models, IntegrityError
from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Q
from django.dispatch import receiver
from django.core.exceptions import *
from django.core.validators import (RegexValidator,
        validate_ipv46_address,
        MinLengthValidator)
import multiprocessing
from tabulate import tabulate
from re import compile
from netaddr import *
from django.db.models import options

options.DEFAULT_NAMES = options.DEFAULT_NAMES + ('history_model', 'history_fk', )
def handleNetaddrError(wrapped):
    '''Decorator to capture errors raised by netaddr
    library. Exceptions were observed at the following
    URL:

    https://github.com/netaddr/netaddr/blob/master/netaddr/core.py
    '''

    def wrapper(*args, **kwargs):

        try:

            return wrapped(*args, **kwargs)

        except (AddrFormatError, AddrConversionError, 
                NotRegisteredError):

            raise ValidationError(
                'Invalid MAC/IP address supplied'
            )

    return wrapper

MAC_REGEXP = compile('(?:[0-9a-fA-F]:?){12}')
validateIP = validate_ipv46_address

def validateMAC(value) -> bool:
    '''Use a regex to validate the format of a MAC address.

    Returns a boolean.
    '''

    return [False, True][re.match(MAC_REGEXP, value)]

def validateAddress(value) -> bool:
    '''Validate a given MAC or IP address value.

    Raises ValidationError upon failure.
    '''

    try:
        validateIP(value)
        return True
    except:
        pass

    if not validateMAC(value):
        raise ValidationError(
            f'Invalid address supplied: {value}')

class GOCManager(models.Manager):
    '''Shortcuts to get_or_create and update_or_create
    Manager methods.
    '''

    def create(cls, import_info, *args, **kwargs):
        instance = super().create(*args, **kwargs)
        cls.updateHistory(instance, import_info)
        return instance

    def goc(cls, import_info, defaults=None, *args, **kwargs):
        instance, created = super().get_or_create(defaults=defaults, *args, **kwargs)
        cls.updateHistory(instance, import_info)
        return instance, created

    def uoc(cls, import_info, defaults=None, *args, **kwargs):
        instance, created = super().update_or_create(defaults=defaults, *args, **kwargs)
        cls.updateHistory(instance, import_info)
        return instance, created

    @staticmethod
    def updateHistory(instance, import_info):

        if not hasattr(instance._meta, 'history_fk'):
            return None

        # =================================
        # CREATE THE HISTORY FOR THE OBJECT
        # =================================

        # Import history will contain a complete duplicate of the
        # current instance, thereby allowing us to review how the
        # state of that instance changes over the course of multiple
        # imports

        # Duplicate the current state of the object
        # Each field is copied into a dictionary
        fields = {
                attr.name:getattr(instance,attr.name) for attr in
                instance._meta.fields if attr.name != 'id'
            }

        # Get the foreign key value from the current object from instance
        # class
        fields[instance._meta.history_fk]=instance
        fields['import_info']=import_info

        # Initialize and save the object
        record = instance._meta.history_model.objects.create(**fields)

        print(instance, import_info, fields, record)

# ================
# ImportInfo Model
# ================

class ImportInfo(models.Model):

    file_path = models.CharField(
        max_length=1000,
    )

    sha256sum = models.CharField(
        max_length=32,
        validators=[MinLengthValidator(32)]
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['file_path','sha256sum'],
                name='unique_file_path_sha256sum'
            )
        ]

    def __repr__(self):

        return '<ImportInfo id=({}) file_path=("{}") sha256sum=("{}")>'.format(
            self.id,
            self.file_path,
            self.sha256sum)

class BaseHistoryModel(models.Model):

    objects = GOCManager()

    import_info = models.ForeignKey(
        ImportInfo,
        null=True,
        on_delete=models.SET_NULL)

    class Meta:
        abstract = True

class BaseModel(models.Model):

    objects = GOCManager()

    class Meta:
        abstract = True

# =============
# ADDRESS MODEL
# =============

ADDRESS_TYPE_CHOICES=(
    ('ipv4','ipv4',),
    ('ipv6','ipv6',),
    ('mac','mac',),
)

def addressToInt(wrapped):
    '''Remove "address" from kwargs and convert the value
    to an integer, which is then inserted into kwargs as
    "int". This should make things more efficient at the
    database layer, hopefully.
    '''

    def wrapper(*args, **kwargs):

        if not 'int' in kwargs and 'address' in kwargs:

            # Convert the address to an integer value
            if kwargs['address'].find(':') > -1:

                # Try MAC address first
                i = int(EUI(kwargs['address']))

            else:

                # Try IP address otherwise
                i = int(IPAddress(kwargs['address']))


            kwargs['int'] = i

        # Remove the address value
        if 'address' in kwargs: del(kwargs['address'])
        return wrapped(*args, **kwargs)

    return wrapper

class AddressManager(GOCManager):
    '''Override the "get" and "filter" methods such that
    searching with an integer value is preferred over the
    address value.
    '''

    @addressToInt
    def get(self, **kwargs):
        return super().get(**kwargs)

    @addressToInt
    def filter(self, **kwargs):
        return super().filter(**kwargs)

class Address(models.Model):

    objects = AddressManager()

    import_info = models.ForeignKey(
        ImportInfo,
        null=True,
        on_delete=models.SET_NULL)

    address = models.CharField(
        max_length=17,
        validators=[validateAddress])

    int = models.PositiveBigIntegerField(
        null=True,
        unique=True)

    addrtype = models.CharField(
        max_length=4,
        choices=ADDRESS_TYPE_CHOICES,
        default='ipv4')

    vendor = models.CharField(null=True,
        max_length=1000)

    host = models.ForeignKey('Host',
        on_delete=models.CASCADE,
        related_name='addresses',
        null=True)

    @property
    def type(self):
        '''Shortcut to the addrtype attribute defined by the
        NMap dtd.
        '''

        return self.addrtype

    def __str__(self):
        return self.address

    @handleNetaddrError
    def save(self, **kwargs):
        '''Override the save method to capture the address
        as an integer and the protocol version.
        '''

        if self.int and self.address:
            return super().save(**kwargs)
        elif self.int:
            return self.saveFromInt(**kwargs)
        else:
            return self.saveFromAddress(**kwargs)

    def saveFromInt(self, **kwargs):
        '''Translate the integer value to a string address and
        save the object.
        '''

        if self.addrtype == 'mac':

            self.address = ':'.join(
                str(EUI(self.int)).split('-')
            )

        else:

            self.address = str(
                str(IPAddress(self.int))
            )

        return super().save(**kwargs)

    def saveFromAddress(self, **kwargs):
        '''Translate the string value to an integer and save the
        object.
        '''

        if self.addrtype == 'mac':

            self.int = int(EUI(self.address))

        else:

            ip = IPAddress(self.address)
            self.int = int(ip)

        return super().save(**kwargs)

# ==============
# HOSTNAME MODEL
# ==============

class Hostname(models.Model):

    objects = GOCManager()

    import_info = models.ForeignKey(
        ImportInfo,
        null=True,
        on_delete=models.SET_NULL)

    name = models.CharField(max_length=2000,
        unique=True)

    addresses = models.ManyToManyField(Address,
        related_query_name='addresses',
        related_name='hostnames')

    def __repr__(self):

        return '<Hostname name=("{}") id=("{}")>'.format(
            self.name,
            self.id)

# ==========
# HOST MODEL
# ==========

HOST_STATUS_CHOICES = (
    ('up','up',),
    ('down','down',),
    ('unknown','unknown',),
    ('skipped','skipped',),
)

class BaseHostModel(BaseModel):

    status = models.CharField(
        max_length=7,
        choices=HOST_STATUS_CHOICES)

    status_reason = models.CharField(
        max_length=100)

    class Meta:
        abstract = True

    def __repr__(self):

        return '<Host id=({}) status=("{}")) Status_reason=("{}")>' \
                .format(
                    self.id,
                    self.status,
                    self.status_reason)

class HostHistory(BaseHostModel,BaseHistoryModel,):

    host = models.ForeignKey(
        'nmap.Host',
        on_delete = models.CASCADE,
        related_name='hosts')

    def __repr__(self):

        return '<HostHistory id=({}) status=("{}")) Status_reason' \
                '=("{}")>'.format(
                    self.id,
                    self.status,
                    self.status_reason)

class Host(BaseHostModel):

    class Meta:
        history_model = HostHistory
        history_fk = 'host'

    def toTable(self,protocols=['tcp'],show_id=False):

        addresses, port_rows = [], []

        for address in self.addresses.all():
            addresses.append(str(address))

            if protocols:
                qs = Q(protocol=protocols[0])
                [qs | Q(protocol=p) for p in protocols[1:]]
                port_rows = (p.toRow() for p in address.ports.filter(qs))
        
        addresses = ", ".join(
            (a.address for a in self.addresses.all())
        ) + ' (status: {} reason: {})'.format(
            self.status,
            self.status_reason
        )

        if show_id: addresses = f'[{self.id}] '+addresses

        header = addresses
        if protocols:
            border = '-'*len(addresses)
            header = '{border}\n{addresses}\n' \
                '{border}\n'.format(
                    border=border,
                    addresses=addresses,
                    status=self.status,
                    reason=self.status_reason
                )

        return header+tabulate(port_rows,
                tablefmt='plain',
                headers=Port.ROW_HEADERS)

# ==========
# PORT MODEL
# ==========

PORT_PROTOCOL_CHOICES = (
    ('ip','ip',),
    ('tcp','tcp',),
    ('udp','udp',),
    ('sctp','sctp',),
)

class BasePortModel(BaseModel):

    portid = models.PositiveIntegerField()
    state = models.CharField(max_length=1000)
    reason = models.CharField(max_length=1000)
    protocol = models.CharField(max_length=4,
        choices = PORT_PROTOCOL_CHOICES)

    address = models.ForeignKey(Address,
        on_delete=models.CASCADE,
        related_query_name='addresses',
        related_name='ports')

    class Meta:
        abstract = True
        constraints = [
            models.UniqueConstraint(
                fields=['portid','protocol','address','reason'],
                name='unique_address_port'
            )
        ]

    @property
    def number(self):
        return self.portid

    def __repr__(self):
        return '<Port id=({}) protocol=("{}") ' \
                'number=("{}") state=("{}") reason=("{}")>'.format(
                    str(self.id),
                    self.protocol,
                    self.portid,
                    self.state,
                    self.reason)

class PortHistory(BasePortModel,BaseHistoryModel):

    address = models.ForeignKey(Address,
        on_delete=models.CASCADE)

    port = models.ForeignKey(
        'nmap.Port',
        on_delete = models.CASCADE)

    class Meta:
        constraints = []

    def __repr__(self):
        return '<PortHistory id=({}) protocol=("{}") ' \
                'number=("{}") state=("{}") reason=("{}")>'.format(
                    str(self.id),
                    self.protocol,
                    self.portid,
                    self.state,
                    self.reason)

class Port(BasePortModel):

    class Meta(BasePortModel.Meta):
        history_model = PortHistory
        history_fk = 'port'

    ROW_HEADERS = ['Protocol','Number','State','Reason']

    def toRow(self):
        return [self.protocol, self.number, self.state, self.reason]

# ============
# SCRIPT MODEL
# ============

class BaseScriptModel(BaseModel):

    nmap_id = models.CharField(max_length=1000)
    output = models.TextField()

    port = models.ForeignKey(Port,
        on_delete=models.CASCADE,
        related_name='scripts')

    class Meta:
        abstract = True

class ScriptHistory(BaseScriptModel, BaseHistoryModel):

    port = models.ForeignKey(Port,
        on_delete=models.CASCADE)

    script = models.ForeignKey(
        'nmap.Script',
        on_delete = models.CASCADE)

class Script(BaseScriptModel):

    class Meta:
        history_model = ScriptHistory
        history_fk = 'script'

# =============
# SERVICE MODEL
# =============

class BaseServiceModel(BaseModel):

    name = models.CharField(max_length=1000)
    conf = models.CharField(max_length=1,
        null=True)
    method = models.CharField(max_length=5,
        null=True)
    version = models.CharField(max_length=1000,
        null=True)
    product = models.CharField(max_length=1000,
        null=True)
    extrainfo = models.TextField(null=True)
    tunnel = models.CharField(null=True,
        max_length=100)
    ostype = models.CharField(max_length=1000,
        null=True)
    devicetype = models.CharField(max_length=1000,
        null=True)
    proto = models.CharField(max_length=1000,
        null=True)
    servicefp = models.TextField(null=True)

    rpcnum = models.PositiveIntegerField(null=True)
    lowver = models.PositiveIntegerField(null=True)
    highver = models.PositiveIntegerField(null=True)

    hostname = models.ForeignKey(Hostname,
        null=True,
        on_delete=models.SET_NULL,
        related_name='services')

    port = models.OneToOneField(Port,
        on_delete=models.CASCADE,
        related_name='service')

    class Meta:
        abstract = True

    def __repr__(self):
        return '<Service id=({}) name=("{}") version=("{}") ' \
            'proto=("{}") extrainfo=("{}")>'.format(
                self.id,
                self.name,
                self.version,
                self.extrainfo,
                self.proto)

class ServiceHistory(BaseServiceModel, BaseHistoryModel):

    service = models.ForeignKey(
        'nmap.Service',
        on_delete=models.CASCADE)

    hostname = models.ForeignKey(
        Hostname,
        null=True,
        on_delete=models.SET_NULL)

    port = models.ForeignKey(
        Port,
        on_delete=models.CASCADE)

    def __repr__(self):
        return '<ServiceHistory id=({}) name=("{}") version=("{}") ' \
            'proto=("{}") extrainfo=("{}")>'.format(
                self.id,
                self.name,
                self.version,
                self.extrainfo,
                self.proto)

class Service(BaseServiceModel):

    class Meta:
        history_model = ServiceHistory
        history_fk = 'service'
