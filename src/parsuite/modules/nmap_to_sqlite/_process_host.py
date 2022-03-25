import nmap
from parsuite.abstractions.xml.generic.network_host import *

def processHost(host):
    '''
    Process a network host and make relevant associations for
    it in a database using Django's ORM. Database configuraitons
    must be applied using django.conf.settings.

    - host - network_host.Host object generated by a parser
    module from Parsuite
    '''

    # =================================
    # INITIALIZE THE HOST AND ADDRESSES
    # =================================

    dbhost, mac, ipv4, ipv6 = None, None, None, None

    if host.mac_address:

        mac, mac_created = nmap.models.Address.objects.goc(
                address=host.mac_address,
                addrtype='mac')

        if mac.host: dbhost = mac.host

    if host.ipv4_address:

        ipv4, ipv4_created = nmap.models.Address.objects.goc(
                address=host.ipv4_address,
                addrtype='ipv4')

        if not dbhost and ipv4.host: dbhost = ipv4.host

    if host.ipv6_address:

        ipv6, ipv6_created = nmap.models.Address.objects.goc(
                address=host.ipv6_address,
                addrtype='ipv6')

        if not dbhost and ipv6.host: dbhost = ipv6.host

    # =======================================
    # CREATE NEW HOST IF IT WAS NOT RECOVERED
    # =======================================

    if not dbhost:

        if not mac and not ipv4 and not ipv6:
            return False

        dbhost = nmap.models.Host()
        dbhost.save()

        # Associate the addresses
        if mac:
            mac.host = dbhost
            mac.save()

        if ipv4:
            ipv4.host = dbhost
            ipv4.save()

        if ipv6:
            ipv6.host = dbhost
            ipv6.save()

    # =====================
    # HANDLE THE HOSTSTATUS
    # =====================

    host_status, host_status_created = nmap.models.HostStatus \
        .objects.goc(
            host=dbhost,
            status=host.status,
            status_reason=host.status_reason
        )

    # ================
    # HANDLE HOSTNAMES
    # ================

    if mac: mac.save()
    if ipv4: ipv4.save()
    if ipv6: ipv6.save()

    for hn in host.hostnames:

        addresses = []

        if ipv4: addresses.append(ipv4)
        if ipv6: addresses.append(ipv6)
        if mac:  addresses.append(mac)

        dbhn, created = nmap.models.Hostname.objects.goc(
            name=hn)
        dbhn.addresses.add(*addresses)

    # ============
    # HANDLE PORTS
    # ============

    for protocol in ['ip','tcp','udp','sctp']:

        ports = getattr(host,f'{protocol}_ports')

        for port in ports.values():

            defaults = {
                'portid':port.portid,
                'state':port.state,
                'protocol':protocol,
                'reason':port.reason,
            }

            # get_or_create each of the ports
            if ipv4:

                dbport, created = nmap.models.Port.objects.goc(
                    defaults=defaults,
                    address=ipv4,
                    portid=port.portid)

            if ipv6:

                dbport, created = nmap.models.Port.objects.goc(
                    defaults=defaults,
                    address=ipv6,
                    portid=port.portid)

            # ==============
            # HANDLE SCRIPTS
            # ==============

            if port.service:

                defaults = {
                    k:getattr(port.service,k) for k in
                    Service.ATTRIBUTES
                }

                dbservice, created = nmap.models.Service.objects \
                    .uoc(
                        defaults=defaults,
                        port=dbport
                    )

            # ===============
            # HANDLE SERVICES
            # ===============

            if port.scripts:

                for script in port.scripts:

                    dbscript, created = nmap.models.Script.objects.uoc(
                        defaults={'nmap_id':script.id,'output':script.output},
                        port=dbport)
