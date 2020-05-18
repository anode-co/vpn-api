from django.db import models
from django.utils.translation import gettext_lazy as _
from django.utils.text import slugify
from django.db.models.signals import pre_save


class VpnClientEvent(models.Model):
    """VPN Client Event."""

    ERROR_CONNECTION_FAILED = "connection_failed"
    ERROR_DISCONNECTION = "disconnection"
    ERROR_ROUTE_STOPPED = "route_stopped"
    ERROR_CJDNS_CRASH = "cjdns_crash"
    ERROR_VPN_CLIEN_CONNECTED = "connection"
    ERROR_VPN_CLIENT_DISCONNECTED = "disconnection"
    ERROR_CJDROUTE = "cjdroute"
    ERROR_CJDNS_SOCKET = "cjdns_socket"
    ERROR_VPN_SERVICE = "vpn_service"
    ERROR_OTHER = "other"

    ERROR_CHOICES = [
        (ERROR_CONNECTION_FAILED, _('Could not connect')),
        (ERROR_DISCONNECTION, _('Unexpected disconnection')),
        (ERROR_ROUTE_STOPPED, _('Connected but unable to route traffic')),
        (ERROR_CJDNS_CRASH, _('CJDNS crashed')),
        (ERROR_VPN_CLIEN_CONNECTED, _('VPN client connected')),
        (ERROR_VPN_CLIENT_DISCONNECTED, _('VPN client disconnected')),
        (ERROR_CJDROUTE, _('Cjdroute problem')),
        (ERROR_CJDNS_SOCKET, _('Cjdns socket error')),
        (ERROR_VPN_SERVICE, _('VPN service problem')),
        (ERROR_OTHER, _('Other reason')),
    ]

    public_key = models.CharField(max_length=64)
    error = models.CharField(max_length=64, choices=ERROR_CHOICES)
    client_software_version = models.CharField(max_length=32)
    client_os = models.CharField(max_length=32)
    client_os_version = models.CharField(max_length=32)
    cpu_utilization_percent = models.CharField(max_length=32, null=True, blank=True)
    available_memory_bytes = models.CharField(max_length=32, null=True, blank=True)
    local_timestamp = models.DateTimeField()
    ip4_address = models.CharField(max_length=15, null=True, blank=True)
    ip6_address = models.CharField(max_length=50, null=True, blank=True)
    message = models.CharField(max_length=100)
    previous_android_log = models.TextField(null=True, blank=True)
    new_android_log = models.TextField(null=True, blank=True)
    debugging_messages = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        """Represent as String."""
        return "{} on {} {}".format(self.error, self.client_os, self.client_os_version)


class ClientSoftwareVersion(models.Model):
    """Information about the latest Client platform's software version."""

    PLATFORM_ANDROID = 'android'
    PLATFORM_IOS = 'ios'
    PLATFORM_MACOS = 'macos'
    PLATFORM_WINDOWS = 'windows'
    PLATFORM_LINUX = 'linux'

    PLATFORMS = [
        (PLATFORM_ANDROID, _("Android")),
        (PLATFORM_IOS, _("iOS")),
        (PLATFORM_MACOS, _("Mac OS")),
        (PLATFORM_WINDOWS, _("Windows")),
        (PLATFORM_LINUX, _("Linux")),
    ]

    client_os = models.CharField(max_length=20, choices=PLATFORMS, blank=True)
    name = models.CharField(max_length=64, null=True, blank=True)
    slug = models.SlugField(max_length=64, null=True, blank=True)
    major_number = models.PositiveSmallIntegerField()
    minor_number = models.PositiveSmallIntegerField()
    revision_number = models.PositiveSmallIntegerField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    binary_download_url = models.URLField(max_length=300)
    certificate_url = models.URLField(max_length=300)
    release_datetime = models.DateTimeField(auto_now_add=True)

    @property
    def client_software_version(self):
        """Convert version numbers into string."""
        print("getting client software version")
        output = None
        if self.revision_number is None:
            output = '{}-{}.{}'.format(self.client_os, str(self.major_number), str(self.minor_number))
        else:
            output = '{}-{}.{}-{}'.format(self.client_os, str(self.major_number), str(self.minor_number), str(self.revision_number))
        print(output)
        return output

    def __str__(self):
        """Represent as String."""
        return self.client_software_version

    @classmethod
    def pre_save(cls, instance, *args, **kwargs):
        """Pre-save methods. Slugify the name."""
        if instance.name is not None:
            instance.slug = slugify(instance.name)


pre_save.connect(ClientSoftwareVersion.pre_save, sender=ClientSoftwareVersion)


class CjdnsVpnServer(models.Model):
    """Cjdns VPN Server."""

    name = models.CharField(max_length=64)
    public_key = models.CharField(max_length=64)
    bandwidth_bps = models.PositiveIntegerField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    is_approved = models.BooleanField(default=False)
    online_since_datetime = models.DateTimeField(auto_now_add=True, blank=True)
    last_seen_datetime = models.DateTimeField(auto_now=True, blank=True)

    _network_settings = None

    @property
    def network_settings(self):
        """Fetch the network settings if they don't exist."""
        if self._network_settings is None:
            try:
                self._network_settings = CjdnsVpnNetworkSettings.objects.get(cjdns_vpn_server=self)
            except CjdnsVpnNetworkSettings.DoesNotExist:
                pass
        return self._network_settings

    _peering_lines = None

    def peering_lines(self):
        """Fetch the pering lines if they don't exist."""
        if self._peering_lines is None:
            self._peering_lines = CjdnsVpnServerPeeringLine.objects.filter(cjdns_vpn_server=self)
        return self._peering_lines

    _network_settings = None

    def send_new_server_email_to_admin(self, vpn_server):
        """Send an email to an administrator that a new VPN has been added."""
        pass

    def __str__(self):
        """Represent as String."""
        return self.name


class CjdnsVpnServerPeeringLine(models.Model):
    """Peering line for a cjdns VPN Server."""

    cjdns_vpn_server = models.ForeignKey(CjdnsVpnServer, on_delete=models.CASCADE)
    name = models.CharField(max_length=64)
    login = models.CharField(max_length=64)
    password = models.CharField(max_length=64)

    def __str__(self):
        """Represent as String."""
        return self.login


class CjdnsVpnNetworkSettings(models.Model):
    """Network settings for a cjdns VPN Server."""

    cjdns_vpn_server = models.OneToOneField(CjdnsVpnServer, on_delete=models.CASCADE)
    uses_nat = models.BooleanField(default=True)
    per_client_allocation_size = models.CharField(max_length=32, default='/0')

    _nat_exit_ranges = None

    @property
    def nat_exit_ranges(self):
        """Fetch the exit ranges settings if they don't exist."""
        if self._nat_exit_ranges is None:
            self._nat_exit_ranges = NetworkExitRange.objects.filter(cjdns_vpn_network_settings=self, type=NetworkExitRange.TYPE_NAT_EXIT)
        return self._nat_exit_ranges

    _client_allocation_ranges = None

    @property
    def client_allocation_ranges(self):
        """Fetch the exit ranges settings if they don't exist."""
        if self._client_allocation_ranges is None:
            self._client_allocation_ranges = NetworkExitRange.objects.filter(cjdns_vpn_network_settings=self, type=NetworkExitRange.TYPE_CLIENT_ALLOCATION)
        return self._client_allocation_ranges

    class Meta:
        """Meta-information for the class."""

        verbose_name_plural = "Cjdns Vpn Network Settings"

    def __str__(self):
        """Represent as String."""
        if self.uses_nat:
            return "NAT"
        else:
            return "Non-NAT"


class NetworkExitRange(models.Model):
    """Network exit range."""

    TYPE_NAT_EXIT = 'nat_exit'
    TYPE_CLIENT_ALLOCATION = 'client_allocation'
    TYPES = [
        (TYPE_NAT_EXIT, _('Exit Range')),
        (TYPE_CLIENT_ALLOCATION, _('Allocation Range')),
    ]

    cjdns_vpn_network_settings = models.ForeignKey(CjdnsVpnNetworkSettings, on_delete=models.CASCADE)
    type = models.CharField(max_length=32, choices=TYPES)
    min = models.CharField(max_length=64)
    max = models.CharField(max_length=64)

    def __str__(self):
        """Represent as String."""
        return "{} - {}".format(self.min, self.max)
