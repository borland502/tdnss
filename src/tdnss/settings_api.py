import logging
from typing import List

from tdnss import OK, ERROR
from tdnss.baseresponse import BaseResponse
from tdnss.connection import Connection

log = logging.getLogger(__name__)


class SettingsResponse(BaseResponse):
    pass


class SettingsAPI:
    def __init__(self, connection: Connection):
        self.connection = connection

    def set_dns_settings(self, dns_server_domain=None, dns_server_local_endpoints=None,
                         web_service_local_addresses=None,
                         web_service_http_port=None, web_service_enable_tls=None, web_service_tls_port=None,
                         web_service_tls_certificate_path=None, web_service_tls_certificate_password=None,
                         enable_dns_over_http=None, enable_dns_over_tls=None, enable_dns_over_https=None,
                         dns_tls_certificate_path=None, dns_tls_certificate_password=None, prefer_ipv6=None,
                         log_queries=None, allow_recursion=None, allow_recursion_only_for_private_networks=None,
                         randomize_name=None, cache_prefetch_eligibility=None, cache_prefetch_trigger=None,
                         cache_prefetch_sample_interval_in_minutes=None,
                         cache_prefetch_sample_eligibility_hits_per_hour=None,
                         proxy_type=None, proxy_address=None, proxy_port=None, proxy_username=None, proxy_password=None,
                         proxy_bypass=None, forwarders=None, forwarder_protocol=None, use_nx_domain_for_blocking=None,
                         block_list_urls=None, tsig_keys=None):
        # Construct the URL for the API endpoint
        endpoint_url = "settings/set"

        # Prepare the request parameters
        params = {
            "dnsServerDomain": dns_server_domain,
            "dnsServerLocalEndPoints": dns_server_local_endpoints,
            "webServiceLocalAddresses": web_service_local_addresses,
            "webServiceHttpPort": web_service_http_port,
            "webServiceEnableTls": web_service_enable_tls,
            "webServiceTlsPort": web_service_tls_port,
            "webServiceTlsCertificatePath": web_service_tls_certificate_path,
            "webServiceTlsCertificatePassword": web_service_tls_certificate_password,
            "enableDnsOverHttp": enable_dns_over_http,
            "enableDnsOverTls": enable_dns_over_tls,
            "enableDnsOverHttps": enable_dns_over_https,
            "dnsTlsCertificatePath": dns_tls_certificate_path,
            "dnsTlsCertificatePassword": dns_tls_certificate_password,
            "preferIPv6": prefer_ipv6,
            "logQueries": log_queries,
            "allowRecursion": allow_recursion,
            "allowRecursionOnlyForPrivateNetworks": allow_recursion_only_for_private_networks,
            "randomizeName": randomize_name,
            "cachePrefetchEligibility": cache_prefetch_eligibility,
            "cachePrefetchTrigger": cache_prefetch_trigger,
            "cachePrefetchSampleIntervalInMinutes": cache_prefetch_sample_interval_in_minutes,
            "cachePrefetchSampleEligibilityHitsPerHour": cache_prefetch_sample_eligibility_hits_per_hour,
            "proxyType": proxy_type,
            "proxyAddress": proxy_address,
            "proxyPort": proxy_port,
            "proxyUsername": proxy_username,
            "proxyPassword": proxy_password,
            "proxyBypass": proxy_bypass,
            "forwarders": forwarders,
            "forwarderProtocol": forwarder_protocol,
            "useNxDomainForBlocking": use_nx_domain_for_blocking,
            "blockListUrls": block_list_urls,
            "tsigKeys": tsig_keys
        }

        r = self.connection._get(endpoint_url, params)

        if self.connection._is_ok(r):
            resp = r.json().get("response")
            return SettingsResponse(OK, data=resp)

        else:
            log.debug(f"{endpoint_url=}, {r=}")
            log.debug(self.connection._get_error_message(r))
            return SettingsResponse(ERROR, self.connection._get_error_message(r))

    def get_settings(self):
        endpoint_url = 'settings/get'

        r = self.connection._get(endpoint_url, {})

        if self.connection._is_ok(r):
            resp = r.json().get("response")
            return SettingsResponse(OK, data=resp)

        else:
            log.debug(f"{endpoint_url=}, {r=}")
            log.debug(self.connection._get_error_message(r))
            return SettingsResponse(ERROR, "Could not get settings")

    def get_tsig_key_names(self):
        endpoint_url = 'settings/getTsigKeyNames'

        r = self.connection._get(endpoint_url, {})

        if self.connection._is_ok(r):
            resp = r.json().get("response")
            tsig_key_names = resp.get("tsigKeyNames")
            return SettingsResponse(OK, data=tsig_key_names)

        else:
            log.debug(f"{endpoint_url=}, {r=}")
            log.debug(self.connection._get_error_message(r))
            return SettingsResponse(ERROR, "Could not get tsig keys")

    def add_tsig_key(self, zone: str, algo: str = 'hmac-sha256', secret: str = ""):
        if zone in self.get_tsig_key_names().data:
            return SettingsResponse(ERROR, "Key already exists; use update API to update")

        settings = self.get_settings()
        tsig_list: List = settings.data["tsigKeys"]

        new_key = {
            'algorithmName': algo,
            'keyName': zone,
            'sharedSecret': secret
        }
        tsig_list.append(new_key)

        tsig_array = map(lambda key: f"{key['keyName']}|{key['sharedSecret']}|{key['algorithmName']}", tsig_list)
        tsig_string = "|".join(tsig_array)

        return self.set_dns_settings(tsig_keys=tsig_string)

    def rm_tsig_key(self, zone: str):
        settings = self.get_settings()
        tsig_list: List = settings.data["tsigKeys"]

        tsig_map = filter(lambda key: key != zone, tsig_list)
        tsig_array = map(lambda key: f"{key['keyName']}|{key['sharedSecret']}|{key['algorithmName']}", tsig_map)
        if len(list(tsig_array)) == 0:
            tsig_string = "false"
        else:
            tsig_string = "|".join(tsig_array)

        return self.set_dns_settings(tsig_keys=tsig_string)
