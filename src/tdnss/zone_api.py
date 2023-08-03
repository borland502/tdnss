import logging

from tdnss import OK, ERROR
from tdnss.baseresponse import BaseResponse
from dataclasses import dataclass

from tdnss.connection import Connection

log = logging.getLogger(__name__)

@dataclass
class ZoneResponse(BaseResponse):
    """A response from Connection.

    For more information, see BaseResponse.
    """


class ZoneAPI:
    def __init__(self, connection: Connection):
        self.connection = connection

    def create_zone(self, zone, zone_type="Primary", primary_name_server_addresses=None, zone_transfer_protocol=None,
                    tsig_key_name=None, protocol=None, forwarder=None, dnssec_validation=None, proxy_type=None,
                    proxy_address=None, proxy_port=None, proxy_username=None, proxy_password=None):

        base_url = 'zones/create'
        # Prepare the request parameters
        params = {
            "zone": zone,
            "type": zone_type,
            "primaryNameServerAddresses": primary_name_server_addresses,
            "zoneTransferProtocol": zone_transfer_protocol,
            "tsigKeyName": tsig_key_name,
            "protocol": protocol,
            "forwarder": forwarder,
            "dnssecValidation": dnssec_validation,
            "proxyType": proxy_type,
            "proxyAddress": proxy_address,
            "proxyPort": proxy_port,
            "proxyUsername": proxy_username,
            "proxyPassword": proxy_password,
        }

        r = self.connection._get(base_url, params)

        if self.connection._is_ok(r):
            resp = r.json().get("response")
            domain = resp.get("domain")
            return ZoneResponse(OK, data=domain)

        else:
            log.debug(f"{base_url=}, {r=}")
            log.debug(self.connection._get_error_message(r))
            return ZoneResponse(ERROR, "Could not create zone")


    def delete_zone(self, zone: str):
        base_url = "zones/delete"
        params = {
            "zone": zone
        }

        r = self.connection._get(base_url, params)

        if self.connection._is_ok(r):
            resp = r.json().get("response")
            return ZoneResponse(OK)

        else:
            log.debug(f"{base_url=}, {r=}")
            log.debug(self.connection._get_error_message(r))
            return ZoneResponse(ERROR, "Could not delete zone")
