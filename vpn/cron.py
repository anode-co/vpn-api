from django_cron import CronJobBase, Schedule
from .models import (
    CjdnsVpnServer,
)
import requests


class VerifyActiveVpnServersCron(CronJobBase):
    """Verify active VPN servers.

    Verify which VPN servers are active
    by asking the route server for verification.
    """

    RUN_EVERY_MINS = 1 * 60 * 60  # every day

    schedule = Schedule(run_every_mins=RUN_EVERY_MINS)
    code = 'anode-co.verify-servers'    # a unique code
    VPN_VERIFICATION_ENDPOINT = 'http://h.snode.cjd.li/api/ni/'
    HTTP_TIMEOUT_SECONDS = 1

    def get_queryset(self):
        """Get all real vpn servers."""
        return CjdnsVpnServer.objects.filter(is_approved=True, is_fake=False)

    def build_verification_url(self, cjdns_vpn_server):
        """Build the verification endpoint url."""
        return '{}{}'.format(
            self.VPN_VERIFICATION_ENDPOINT,
            cjdns_vpn_server.cjdns_public_ip
        )

    def do(self):
        """Loop through vpn servers and test if each one is active."""
        vpn_servers = self.get_queryset()
        updated_vpn_servers = []
        for vpn_server in vpn_servers:
            # assume vpn is not alive
            is_active = False
            if vpn_server.cjdns_public_ip:
                url = self.build_verification_url(vpn_server)
                try:
                    response = requests.get(
                        url,
                        timeout=self.HTTP_TIMEOUT_SECONDS
                    )
                    if response.status_code == 200:
                        if "node" in response.json():
                            is_active = True
                except requests.exceptions.Timeout:
                    # Can't reach route server for verification
                    break
                except Exception:
                    # can't reach route server for verification
                    break
            if is_active != vpn_server.is_active:
                vpn_server.is_active = is_active
                updated_vpn_servers.append(vpn_server)
        if len(updated_vpn_servers) > 0:
            CjdnsVpnServer.objects.bulk_update(
                updated_vpn_servers,
                ['is_active'],
                batch_size=1000
            )
