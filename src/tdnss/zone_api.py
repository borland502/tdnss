import logging

from tdnss import OK, ERROR
from tdnss.baseresponse import BaseResponse
from dataclasses import dataclass

from tdnss.connection import Connection

from enum import auto
from strenum import StrEnum

log = logging.getLogger(__name__)


class RFC2136Options(StrEnum):
    Deny = auto()
    Allow = auto()
    AllowOnlyZoneNameServers = auto()
    AllowOnlySpecifiedIpAddresses = auto()
    AllowBothZoneNameServersAndSpecifiedIpAddresses = auto()


@dataclass
class ZoneResponse(BaseResponse):
    """A response from Connection.

    For more information, see BaseResponse.
    """


class ZoneAPI:
    def __init__(self, connection: Connection):
        self.connection = connection

    def create_zone(
        self,
        zone,
        zone_type="Primary",
        primary_name_server_addresses=None,
        zone_transfer_protocol=None,
        tsig_key_name=None,
        protocol=None,
        forwarder=None,
        dnssec_validation=None,
        proxy_type=None,
        proxy_address=None,
        proxy_port=None,
        proxy_username=None,
        proxy_password=None,
    ):
        base_url = "zones/create"
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
        params = {"zone": zone}

        r = self.connection._get(base_url, params)

        if self.connection._is_ok(r):
            return ZoneResponse(OK)

        else:
            log.debug(f"{base_url=}, {r=}")
            log.debug(self.connection._get_error_message(r))
            return ZoneResponse(ERROR, "Could not delete zone")

    def set_zone_options(
        self,
        zone,
        disabled=None,
        zone_transfer=None,
        zone_transfer_name_servers=None,
        zone_transfer_tsig_key_names=None,
        notify=None,
        notify_name_servers=None,
        update_policy=RFC2136Options.Deny,
        update_ip_addresses=None,
        update_tsig_key_name=None,
    ):
        # Construct the URL for the API endpoint
        endpoint_url = f"zones/options/set"

        # Prepare the request parameters
        params = {
            "zone": zone,
            "disabled": disabled,
            "zoneTransfer": zone_transfer,
            "zoneTransferNameServers": zone_transfer_name_servers,
            "zoneTransferTsigKeyNames": zone_transfer_tsig_key_names,
            "notify": notify,
            "notifyNameServers": notify_name_servers,
            "update": update_policy,
            "updateIpAddresses": update_ip_addresses,
        }

        # `updateSecurityPolicies` (optional): A pipe `|` separated table data of security policies
        # with each row containing the TSIG keys name, domain name, and comma separated record types
        # that are allowed. Use wildcard domain name to specify all sub domain names. Set this
        # option to `false` to clear all security policies and stop TSIG authentication.
        # This option is valid only for Primary zones.
        if update_tsig_key_name is not None:
            params["updateSecurityPolicies"] = f"{update_tsig_key_name}|*.{zone}|any"

        params = {k: v for (k, v) in params.items() if v is not None}

        r = self.connection._get(endpoint_url, params)

        if self.connection._is_ok(r):
            resp = r.json().get("response")
            return ZoneResponse(OK, data=resp)

        else:
            log.debug(f"{endpoint_url=}, {r=}")
            log.debug(self.connection._get_error_message(r))
            return ZoneResponse(ERROR, self.connection._get_error_message(r))
