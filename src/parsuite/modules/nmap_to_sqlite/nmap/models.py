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
from netaddr import IPAddress as ipAddress
from django.db.models import options
from django.dispatch import receiver

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

def validateMAC(value):
    '''Use a regex to validate the format of a MAC address.

    Returns a boolean.
    '''

    # NOTE: Maybe expand this to check against the string version
    # of the address to make sure no disparity exists between the
    # two? Apply the ame logic to IP addresses if so.
    if not re.match(MAC_REGEXP, value):
        raise ValidationError(
            f'Invalid MAC address supplied: {value}')

def updateInstanceHistory(instance, import_info):
    '''Update the history table for a given DB instance.

    The history table will contain a complete duplicate of the state
    of the current object, thereby allowing us to review how it changes
    over the course of multiple imports.

    This is achieved by using attributes set in the Meta class of a
    given model:

    - history_model - A CLASS reference to the model that will be used
    to track the history of the subject model. Upon create/update, the
    instance of the subject model will be copied over into the history
    model.
    - history_fk - The field on the history class where the instance of
    the subject class will be referenced, thereby creating a
    relationship that can be used to access the current state of the
    subject instance.

    - instance - subject instance
    - import_info - import_info object used to track the file/scan
    information
    '''

    # Ignore any instance that does not have a "history_fk" key
    if not hasattr(instance._meta, 'history_fk'):
        return None

    # =================================
    # CREATE THE HISTORY FOR THE OBJECT
    # =================================

    # Duplicate the current state of the object
    # Each field is copied into a dictionary
    fields = {
            attr.name:getattr(instance,attr.name) for attr in
            instance._meta.fields if not attr.name in ['id','int']
        }

    # Get the foreign key value from the current object from instance
    # class. This will be the foreign key value set in the history
    # table to allow a reference back to the updated object.
    fields[instance._meta.history_fk]=instance
    fields['import_info']=import_info

    # Initialize and save the object
    return instance._meta.history_model.objects.create(**fields)

# =================
# CONFIGURE SIGNALS
# =================

#@receiver(models.signals.post_init)
def setupChangeDetection(sender, instance, **kwargs):
    '''Initialize properties to determine if a given instance has been
    changed from since being initialized at the model. The following
    attributes are added to the instance:

    _was_changed - Determines if the instance is changed at save
    _was_new - Determines if the instance was new at post_init
    _cached_fields - Dictionary of the current instance fields
    '''

    # Initialize attributes
    instance._was_changed=False
    instance._was_new=(instance.pk == None)
    instance._cached_fields={}

    # Populate the cache
    for f in instance._meta.fields:

        # Disregard the id
        if f.name == 'id': continue
        instance._cached_fields[f.name]=getattr(instance,f.name)

#@receiver(models.signals.post_save)
def updateChangeDetection(sender, instance, **kwargs):
    '''Determine if the instance has changed since initialization.
    '''

    # Get a list of field keys
    instance_field_keys = instance._cached_fields.keys()

    # Only check for changes when the instance is not new
    if not instance._was_new:

        for field in instance._meta.fields:
            # Iterate over each current field

            # Check only fields that are present in the cache
            if not field.name in instance_field_keys: continue

            # Determine if a change happened
            if instance._cached_fields[field.name] != field.name:
                instance._was_changed = True
                break

class GOCManager(models.Manager):
    '''Shortcuts to get_or_create and update_or_create
    Manager methods. Also implements history updates when an instance
    is managed using one of the following methods:

    - create
    - goc
    - uoc
    '''

    def create(cls, import_info, *args, **kwargs):
        instance = super().create(*args, **kwargs)
        cls.updateHistory(instance, import_info)
        return instance

    def goc(cls, import_info, defaults=None, *args, **kwargs):
        instance, created = super().get_or_create(defaults=defaults,
            *args, **kwargs)
        cls.updateHistory(instance, import_info)
        return instance, created

    def uoc(cls, import_info, defaults=None, *args, **kwargs):
        instance, created = super().update_or_create(defaults=defaults,
            *args, **kwargs)
        cls.updateHistory(instance, import_info)
        return instance, created

    def get_or_create(cls, *args, **kwargs):
        return cls.goc(*args, **kwargs)

    def update_or_create(cls, *args, **kwargs):
        return cls.uoc(*args, **kwargs)

    @staticmethod
    def updateHistory(instance, import_info):
        #if not instance._was_new or not instance._was_changed: return None
        return updateInstanceHistory(instance, import_info)

# ================
# ImportInfo Model
# ================

class ImportInfo(models.Model):
    '''Information related to an import event. Maintains a hashsum
    of a given file, along with file path.
    '''

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

        return '<ImportInfo id=({}) file_path=("{}") sha256sum=("{}' \
            '")>'.format(
                self.id,
                self.file_path,
                self.sha256sum)

class BaseHistoryModel(models.Model):
    '''History model from which all history tables will inherit.
    It provides a relationship to the import_info table, providing
    an index of where the information came from as well as a stateful
    history of how the object has changed over imports.
    '''

    objects = models.Manager()

    import_info = models.ForeignKey(
        ImportInfo,
        on_delete=models.CASCADE)

    class Meta:
        abstract = True

class BaseModel(models.Model):

    objects = GOCManager()

    class Meta:
        abstract = True

    def updateHistory(self, import_info):
        return updateInstanceHistory(self, import_info)

# =============
# ADDRESS MODEL
# =============

ADDRESS_TYPE_CHOICES=(
    ('ipv4','ipv4',),
    ('ipv6','ipv6',),
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
                i = int(ipAddress(kwargs['address']))


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
    def get(self, *args, **kwargs):
        return super().get(**kwargs)

    @addressToInt
    def filter(self, *args, **kwargs):
        return super().filter(*args,**kwargs)

class BaseAddressModel(models.Model):
    '''A base model from which both Internet Protocol (IP) and
    Media Access Control (MAC) addresses can be derived. All instances
    can be associated with a host and must be represented as integer
    value, which is used for uniqueness and searching for efficiency.
    '''

    objects = AddressManager()

    int = models.PositiveBigIntegerField(
        null=True,
        unique=True)

    class Meta:
        abstract = True

    @property
    def classification(self):
        '''Return the string classification for a given IPAddress. None
        is returned when the classifcation has not yet been derived
        after setting `int_classification` and saving the instance.
        '''

        for i, classification in IP_CATEGORY_CHOICES:
            if i == self.int_classification: return classification

        return None

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

        if isinstance(self, MACAddress):

            self.address = ':'.join(
                str(EUI(self.int)).split('-')
            )

        else:

            ip = ipAddress(self.int)
            self.int_classification = checkCategorisation(ip)
            self.address = str(ip)

        return super().save(**kwargs)

    def saveFromAddress(self, **kwargs):
        '''Translate the string value to an integer and save the
        object.
        '''

        if isinstance(self, MACAddress):

            self.int = int(EUI(self.address))

        else:

            ip = ipAddress(self.address)
            self.int_classification = checkCategorisation(ip)
            self.int = int(ip)

        return super().save(**kwargs)

    def update(self, import_info, **kwargs):
        updateInstanceHistory(self, import_info)
        for k,v in kwargs.items():
            setattr(self,k,v)
        self.save()
        return self

def checkCategorisation(netaddr):

    assert isinstance(netaddr,ipAddress),(
        'netattr must be a netaddr.IPAddress object'
    )

    if   netaddr.is_unicast():   return 0
    elif netaddr.is_multicast(): return 1
    elif netaddr.is_private():   return 2
    elif netaddr.is_reserved():  return 3

class BaseMACAddressModel(BaseAddressModel):
    '''Extend the BaseAddress model to include an address field
    and vendor field.

    Notes:
    - It may be efficient to add a vendor table an a FK here
    - No unique is enforced on address for performance reasons
    '''

    address = models.CharField(
        max_length=17,
        validators=[validateMAC])

    vendor = models.CharField(null=True,
        max_length=1000)

    class Meta:
        abstract = True

class MACAddressHistory(BaseHistoryModel,BaseMACAddressModel):
    '''Historical model for MAC addresses.
    '''

    # overriding to avoid duplicate records
    # address can be retrieved via fk
    int = None
    address = models.ForeignKey(
        'nmap.MACAddress',
        on_delete = models.CASCADE,
        related_name='history')


    def __repr__(self):

        return '<MACAddressHistory address=("{}")>'.format(
            self.address
        )

    def save(self, **kwargs):
        return super(BaseAddressModel, self).save(**kwargs)

class MACAddress(BaseMACAddressModel):
    '''Final MACAddress model with a Meta class that allows the
    history model to produce recors.
    '''

    class Meta:
        history_model = MACAddressHistory
        history_fk = 'address'

IP_CATEGORY_CHOICES = (
    (0,'unicast',),
    (1,'multicast',),
    (2,'private',),
    (3,'reserved',),
)

class BaseIPAddressModel(BaseAddressModel):
    '''Extend the BaseAddressModel for IP addresses.
    '''

    # Selection for type: ipv4, or ipv6
    addrtype = models.CharField(
        max_length=4,
        choices=ADDRESS_TYPE_CHOICES)

    # Address value with a max length of 15 and an IP address validator
    address = models.CharField(
        max_length=15,
        validators=[validateIP])

    # Associated MAC address, if present. An IP address can be represented
    # in an Nmap file without a MAC adress if the target IP was not pinged
    mac_address = models.ForeignKey(
        MACAddress,
        null=True,
        on_delete=models.SET_NULL,
        related_name='ip_addresses')

    # Host associated with the IP address
    host = models.ForeignKey('nmap.Host',
        on_delete=models.CASCADE,
        related_name='ip_addresses',
        null=True)

    int_classification = models.PositiveIntegerField(
        null=True,
        choices=IP_CATEGORY_CHOICES)

    class Meta:
        abstract = True

    @property
    def type(self):
        '''Shortcut to the addrtype attribute defined by the
        NMap dtd.
        '''

        return self.addrtype

    def __str__(self):
        return self.address

class IPAddressHistory(BaseHistoryModel,BaseIPAddressModel):
    '''Historical model for IP addresses.
    '''

    # Override the host field to avoid relationship name
    # collisions
    host = models.ForeignKey('nmap.Host',
        on_delete=models.CASCADE,
        related_name='ip_address_host',
        null=True)

    # Override the int field such that multiple instances
    # can reside in the history table
    int = None
    #int = models.PositiveBigIntegerField(
    #    null=True,
    #    unique=False)

    # FK back to the original address
    address = models.ForeignKey(
        'nmap.IPAddress',
        on_delete = models.CASCADE,
        related_name='history')

    mac_address = models.ForeignKey(
        MACAddress,
        null=True,
        on_delete=models.SET_NULL,
        related_name='mac_address_history')

    def __repr__(self):

        return '<IPAddressHistory address=("{}")>'.format(
            self.address
        )

    def save(self, **kwargs):
        return super(BaseAddressModel, self).save(**kwargs)

class IPAddress(BaseIPAddressModel):
    '''IP address model to bind together the history model and
    foreign key.
    '''

    class Meta:
        history_model = IPAddressHistory
        history_fk = 'address'

# ==============
# HOSTNAME MODEL
# ==============
'''Hostnames do not have a history table. Import info is captured as
a foreign key in the Hostname table.
'''

class Hostname(models.Model):

    objects = GOCManager()

    import_info = models.ForeignKey(
        ImportInfo,
        null=True,
        on_delete=models.SET_NULL)

    name = models.CharField(max_length=2000,
        unique=True)

    addresses = models.ManyToManyField(IPAddress,
        related_query_name='ip_addresses',
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

class HostHistory(BaseHistoryModel,BaseHostModel):

    host = models.ForeignKey(
        'nmap.Host',
        on_delete = models.CASCADE,
        related_name='history')

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

    address = models.ForeignKey(IPAddress,
        on_delete=models.CASCADE,
        related_query_name='ip_addresses',
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

class PortHistory(BaseHistoryModel,BasePortModel):

    address = models.ForeignKey(IPAddress,
        on_delete=models.CASCADE,
        related_name='port_history')

    port = models.ForeignKey(
        'nmap.Port',
        on_delete = models.CASCADE,
        related_name='history')

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

    address = models.ForeignKey(IPAddress,
        on_delete=models.CASCADE,
        related_query_name='ip_addresses',
        related_name='ports')

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

class ScriptHistory(BaseHistoryModel,BaseScriptModel):

    port = models.ForeignKey(Port,
        on_delete=models.CASCADE)

    script = models.ForeignKey(
        'nmap.Script',
        on_delete = models.CASCADE,
        related_name='history')

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

class ServiceHistory(BaseHistoryModel,BaseServiceModel):

    service = models.ForeignKey(
        'nmap.Service',
        on_delete=models.CASCADE,
        related_name='history')

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
