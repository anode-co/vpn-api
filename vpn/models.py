from django.db import models
from django.utils.translation import gettext_lazy as _
from django.utils.text import slugify
from django.db.models.signals import pre_save
from django.core.validators import MinValueValidator 


class VpnClientEvent(models.Model):
    """VPN Client Event."""

    ERROR_CONNECTION_FAILED = "connectionFailed"
    ERROR_DISCONNECTION = "disconnection"
    ERROR_ROUTE_STOPPED = "routeStopped"
    ERROR_CJDNS_CRASH = "cjdnsCrash"
    ERROR_VPN_CLIEN_CONNECTED = "connection"
    ERROR_VPN_CLIENT_DISCONNECTED = "disconnection"
    ERROR_CJDROUTE = "cjdroute"
    ERROR_CJDNS_SOCKET = "cjdnsSocket"
    ERROR_VPN_SERVICE = "vpnService"
    ERROR_OTHER = "other"

    ERROR_ROUTE_STOPPED_OLD = "routeStopped"
    ERROR_CJDNS_CRASH_OLD = "cjdnsCrash"
    ERROR_VPN_SERVICE_OLD = "vpnService"

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

        (ERROR_ROUTE_STOPPED_OLD, _('Connected but unable to route traffic')),
        (ERROR_CJDNS_CRASH_OLD, _('CJDNS crashed')),
        (ERROR_VPN_SERVICE_OLD, _('VPN service problem')),
    ]

    public_key = models.CharField(max_length=64, null=True, blank=True)
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

    CPU_ARCH_ALL = 'all'
    CPU_ARCH_I686 = 'i686'
    CPU_ARCH_AARCH64 = 'aarch64'
    CPU_ARCH_ARMV7A = 'armv7a'
    CPU_ARCH_X86_64 = 'X86_64'

    CPU_ARCHITECTURES = [
        (CPU_ARCH_ALL, 'all'),
        (CPU_ARCH_I686, 'i686'),
        (CPU_ARCH_AARCH64, 'aarch64'),
        (CPU_ARCH_ARMV7A, 'armv7a'),
        (CPU_ARCH_X86_64, 'X86_64'),
    ]

    client_os = models.CharField(max_length=20, choices=PLATFORMS, blank=True)
    client_cpu_architecture = models.CharField(max_length=20, choices=CPU_ARCHITECTURES, blank=True)
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
            output = '{}-{}.{}.{}'.format(self.client_os, str(self.major_number), str(self.minor_number), str(self.revision_number))
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

    AUTHORIZATION_ENDPOINT = '/api/0.3/server/authorize/'
    COUNTRIES = [
        ('AF', _('Afghanistan')),
        ('AX', _('Åland Islands')),
        ('AL', _('Albania')),
        ('DZ', _('Algeria')),
        ('AS', _('American Samoa')),
        ('AD', _('Andorra')),
        ('AO', _('Angola')),
        ('AI', _('Anguilla')),
        ('AQ', _('Antarctica')),
        ('AG', _('Antigua and Barbuda')),
        ('AR', _('Argentina')),
        ('AM', _('Armenia')),
        ('AW', _('Aruba')),
        ('AU', _('Australia')),
        ('AT', _('Austria')),
        ('AZ', _('Azerbaijan')),
        ('BS', _('Bahamas (the)')),
        ('BH', _('Bahrain')),
        ('BD', _('Bangladesh')),
        ('BB', _('Barbados')),
        ('BY', _('Belarus')),
        ('BE', _('Belgium')),
        ('BZ', _('Belize')),
        ('BJ', _('Benin')),
        ('BM', _('Bermuda')),
        ('BT', _('Bhutan')),
        ('BO', _('Bolivia (Plurinational State of)')),
        ('BQ', _('Bonaire, Sint Eustatius and Saba')),
        ('BA', _('Bosnia and Herzegovina')),
        ('BW', _('Botswana')),
        ('BV', _('Bouvet Island')),
        ('BR', _('Brazil')),
        ('IO', _('British Indian Ocean Territory (the)')),
        ('BN', _('Brunei Darussalam')),
        ('BG', _('Bulgaria')),
        ('BF', _('Burkina Faso')),
        ('BI', _('Burundi')),
        ('CV', _('Cabo Verde')),
        ('KH', _('Cambodia')),
        ('CM', _('Cameroon')),
        ('CA', _('Canada')),
        ('KY', _('Cayman Islands (the)')),
        ('CF', _('Central African Republic (the)')),
        ('TD', _('Chad')),
        ('CL', _('Chile')),
        ('CN', _('China')),
        ('CX', _('Christmas Island')),
        ('CC', _('Cocos (Keeling) Islands (the)')),
        ('CO', _('Colombia')),
        ('KM', _('Comoros (the)')),
        ('CD', _('Congo (the Democratic Republic of the)')),
        ('CG', _('Congo (the)')),
        ('CK', _('Cook Islands (the)')),
        ('CR', _('Costa Rica')),
        ('CI', _('Côte d\'Ivoire')),
        ('HR', _('Croatia')),
        ('CU', _('Cuba')),
        ('CW', _('Curaçao')),
        ('CY', _('Cyprus')),
        ('CZ', _('Czechia')),
        ('DK', _('Denmark')),
        ('DJ', _('Djibouti')),
        ('DM', _('Dominica')),
        ('DO', _('Dominican Republic (the)')),
        ('EC', _('Ecuador')),
        ('EG', _('Egypt')),
        ('SV', _('El Salvador')),
        ('GQ', _('Equatorial Guinea')),
        ('ER', _('Eritrea')),
        ('EE', _('Estonia')),
        ('SZ', _('Eswatini')),
        ('ET', _('Ethiopia')),
        ('FK', _('Falkland Islands (the) [Malvinas]')),
        ('FO', _('Faroe Islands (the)')),
        ('FJ', _('Fiji')),
        ('FI', _('Finland')),
        ('FR', _('France')),
        ('GF', _('French Guiana')),
        ('PF', _('French Polynesia')),
        ('TF', _('French Southern Territories (the)')),
        ('GA', _('Gabon')),
        ('GM', _('Gambia (the)')),
        ('GE', _('Georgia')),
        ('DE', _('Germany')),
        ('GH', _('Ghana')),
        ('GI', _('Gibraltar')),
        ('GR', _('Greece')),
        ('GL', _('Greenland')),
        ('GD', _('Grenada')),
        ('GP', _('Guadeloupe')),
        ('GU', _('Guam')),
        ('GT', _('Guatemala')),
        ('GG', _('Guernsey')),
        ('GN', _('Guinea')),
        ('GW', _('Guinea-Bissau')),
        ('GY', _('Guyana')),
        ('HT', _('Haiti')),
        ('HM', _('Heard Island and McDonald Islands')),
        ('VA', _('Holy See (the)')),
        ('HN', _('Honduras')),
        ('HK', _('Hong Kong')),
        ('HU', _('Hungary')),
        ('IS', _('Iceland')),
        ('IN', _('India')),
        ('ID', _('Indonesia')),
        ('IR', _('Iran (Islamic Republic of)')),
        ('IQ', _('Iraq')),
        ('IE', _('Ireland')),
        ('IM', _('Isle of Man')),
        ('IL', _('Israel')),
        ('IT', _('Italy')),
        ('JM', _('Jamaica')),
        ('JP', _('Japan')),
        ('JE', _('Jersey')),
        ('JO', _('Jordan')),
        ('KZ', _('Kazakhstan')),
        ('KE', _('Kenya')),
        ('KI', _('Kiribati')),
        ('KP', _('Korea (the Democratic People\'s Republic of)')),
        ('KR', _('Korea (the Republic of)')),
        ('KW', _('Kuwait')),
        ('KG', _('Kyrgyzstan')),
        ('LA', _('Lao People\'s Democratic Republic (the)')),
        ('LV', _('Latvia')),
        ('LB', _('Lebanon')),
        ('LS', _('Lesotho')),
        ('LR', _('Liberia')),
        ('LY', _('Libya')),
        ('LI', _('Liechtenstein')),
        ('LT', _('Lithuania')),
        ('LU', _('Luxembourg')),
        ('MO', _('Macao')),
        ('MK', _('Republic of North Macedonia')),
        ('MG', _('Madagascar')),
        ('MW', _('Malawi')),
        ('MY', _('Malaysia')),
        ('MV', _('Maldives')),
        ('ML', _('Mali')),
        ('MT', _('Malta')),
        ('MH', _('Marshall Islands (the)')),
        ('MQ', _('Martinique')),
        ('MR', _('Mauritania')),
        ('MU', _('Mauritius')),
        ('YT', _('Mayotte')),
        ('MX', _('Mexico')),
        ('FM', _('Micronesia (Federated States of)')),
        ('MD', _('Moldova (the Republic of)')),
        ('MC', _('Monaco')),
        ('MN', _('Mongolia')),
        ('ME', _('Montenegro')),
        ('MS', _('Montserrat')),
        ('MA', _('Morocco')),
        ('MZ', _('Mozambique')),
        ('MM', _('Myanmar')),
        ('NA', _('Namibia')),
        ('NR', _('Nauru')),
        ('NP', _('Nepal')),
        ('NL', _('Netherlands (the)')),
        ('NC', _('New Caledonia')),
        ('NZ', _('New Zealand')),
        ('NI', _('Nicaragua')),
        ('NE', _('Niger (the)')),
        ('NG', _('Nigeria')),
        ('NU', _('Niue')),
        ('NF', _('Norfolk Island')),
        ('MP', _('Northern Mariana Islands (the)')),
        ('NO', _('Norway')),
        ('OM', _('Oman')),
        ('PK', _('Pakistan')),
        ('PW', _('Palau')),
        ('PS', _('Palestine, State of')),
        ('PA', _('Panama')),
        ('PG', _('Papua New Guinea')),
        ('PY', _('Paraguay')),
        ('PE', _('Peru')),
        ('PH', _('Philippines (the)')),
        ('PN', _('Pitcairn')),
        ('PL', _('Poland')),
        ('PT', _('Portugal')),
        ('PR', _('Puerto Rico')),
        ('QA', _('Qatar')),
        ('RE', _('Réunion')),
        ('RO', _('Romania')),
        ('RU', _('Russian Federation (the)')),
        ('RW', _('Rwanda')),
        ('BL', _('Saint Barthélemy')),
        ('SH', _('Saint Helena, Ascension and Tristan da Cunha')),
        ('KN', _('Saint Kitts and Nevis')),
        ('LC', _('Saint Lucia')),
        ('MF', _('Saint Martin (French part)')),
        ('PM', _('Saint Pierre and Miquelon')),
        ('VC', _('Saint Vincent and the Grenadines')),
        ('WS', _('Samoa')),
        ('SM', _('San Marino')),
        ('ST', _('Sao Tome and Principe')),
        ('SA', _('Saudi Arabia')),
        ('SN', _('Senegal')),
        ('RS', _('Serbia')),
        ('SC', _('Seychelles')),
        ('SL', _('Sierra Leone')),
        ('SG', _('Singapore')),
        ('SX', _('Sint Maarten (Dutch part)')),
        ('SK', _('Slovakia')),
        ('SI', _('Slovenia')),
        ('SB', _('Solomon Islands')),
        ('SO', _('Somalia')),
        ('ZA', _('South Africa')),
        ('GS', _('South Georgia and the South Sandwich Islands')),
        ('SS', _('South Sudan')),
        ('ES', _('Spain')),
        ('LK', _('Sri Lanka')),
        ('SD', _('Sudan (the)')),
        ('SR', _('Suriname')),
        ('SJ', _('Svalbard and Jan Mayen')),
        ('SE', _('Sweden')),
        ('CH', _('Switzerland')),
        ('SY', _('Syrian Arab Republic')),
        ('TW', _('Taiwan (Province of China)')),
        ('TJ', _('Tajikistan')),
        ('TZ', _('Tanzania, United Republic of')),
        ('TH', _('Thailand')),
        ('TL', _('Timor-Leste')),
        ('TG', _('Togo')),
        ('TK', _('Tokelau')),
        ('TO', _('Tonga')),
        ('TT', _('Trinidad and Tobago')),
        ('TN', _('Tunisia')),
        ('TR', _('Turkey')),
        ('TM', _('Turkmenistan')),
        ('TC', _('Turks and Caicos Islands (the)')),
        ('TV', _('Tuvalu')),
        ('UG', _('Uganda')),
        ('UA', _('Ukraine')),
        ('AE', _('United Arab Emirates (the)')),
        ('GB', _('United Kingdom of Great Britain and Northern Ireland (the)')),
        ('UM', _('United States Minor Outlying Islands (the)')),
        ('US', _('United States of America (the)')),
        ('UY', _('Uruguay')),
        ('UZ', _('Uzbekistan')),
        ('VU', _('Vanuatu')),
        ('VE', _('Venezuela (Bolivarian Republic of)')),
        ('VN', _('Viet Nam')),
        ('VG', _('Virgin Islands (British)')),
        ('VI', _('Virgin Islands (U.S.)')),
        ('WF', _('Wallis and Futuna')),
        ('EH', _('Western Sahara')),
        ('YE', _('Yemen')),
        ('ZM', _('Zambia')),
        ('ZW', _('Zimbabwe')),
    ]

    name = models.CharField(max_length=64)
    public_key = models.CharField(max_length=64)
    cjdns_public_ip = models.CharField(max_length=40)
    cjdns_public_port = models.PositiveSmallIntegerField(default=6332)
    authorization_server_url = models.CharField(max_length=500)
    bandwidth_bps = models.BigIntegerField(validators=[MinValueValidator(1)], null=True, blank=True)
    is_active = models.BooleanField(default=True)
    is_approved = models.BooleanField(default=False)
    online_since_datetime = models.DateTimeField(auto_now_add=True, blank=True)
    last_seen_datetime = models.DateTimeField(auto_now=True, blank=True)
    region = models.CharField(max_length=200, null=True, blank=True)
    country_code = models.CharField(max_length=2, choices=COUNTRIES, null=True, blank=True)
    is_fake = models.BooleanField(default=False)

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
