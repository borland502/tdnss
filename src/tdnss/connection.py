# Copyright: (c) 2022, JulioLoayzaM
# GPL-3.0-only (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import logging
import requests

from dataclasses import dataclass
from typing import Dict, Tuple

from tdnss import config
from tdnss import OK, ERROR, INVALID_TOKEN, INIT_ERROR
from tdnss.baseresponse import BaseResponse


log = logging.getLogger(__name__)


@dataclass
class ConnectionResponse(BaseResponse):
    """A response from Connection.

    For more information, see BaseResponse.
    """


class Connection:
    """A connection to the DNS server API.

    Assumes server_url is in the form 'http://<server address>/api'.

    See https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md
    for the API documentation.
    """

    def __init__(
        self, server_url: str = "", api_token: str = "", auto_login: bool = False
    ):
        """A connection to the DNS server API.

        For regular use, the server's URL and an API token are needed. If the config
        file exists with the correct info, use the auto_login flag to load it.
        The config file takes precedence.

        To log in with the username/password, only the server URL is required.

        Args:
            server_url:
                The server's URL. The '/api' suffix is added if it was not already
                in the URL.
            api_token:
                An API token. It is assumed to be valid, as no tests are performed.
                If the config file exists, you can use the auto_login flag to load
                the token. Else, use the login method to create a session token.
                To modify this token after creating the Connection, use the
                _set_current_token method.
            auto_login:
                Whether to login automatically when creating a Connection. This loads
                an API token from the config file if it exists.
                Otherwise the user has to call the login method before using other
                methods or an error is raised.

        Note:
            If auto-login is enabled, the server URL is taken from the configuration
            file, meaning that any value given when creating a Connection is ignored.
        """
        # append the '/api' suffix to the server_url if it is missing
        if server_url:
            if not server_url.endswith("/api"):
                if server_url[-1] != "/":
                    server_url += "/"
                server_url += "api"

        self.server_url = server_url
        self.token = api_token

        self.session_token: str = ""
        self.params: Dict[str, str] = {"token": self.token}

        if auto_login:
            self._auto_login()

    ################################ Internal methods ################################

    def _get_status(self, response: requests.Response) -> int:
        """Gets the API response's status from the request Response.

        Args:
            response: The request Response.

        Returns:
            int: The status code.
        """
        try:
            d = response.json()
        except requests.JSONDecodeError as error:
            log.debug(f"JSONDecodeError: {error}")
            return ERROR
        except Exception as error:
            log.debug(error)
            return ERROR

        status = d.get("status")
        if status == "ok":
            return OK
        if status == "error":
            return ERROR
        return INVALID_TOKEN

    def _is_ok(self, response: requests.Response) -> bool:
        """Checks whether the received status is OK.

        Args:
            response: The response to check.

        Returns:
            bool: True is status == OK, False otherwise.
        """
        return self._get_status(response) == OK

    def _get_error_message(self, response: requests.Response) -> str:
        """Gets the error message from a response.

        Args:
            response: Response obtained from a request.

        Returns:
            str: The error message received.
        """
        if self._get_status(response) == ERROR:

            try:
                d = response.json()
            except requests.JSONDecodeError as error:
                log.debug(f"JSONDecodeError: {error}")
                return "An error occurred while decoding the server response"
            except Exception as error:
                log.debug(error)
                return "Unknown error, check the logs"

            msg = d.get("errorMessage")
            return msg

        elif self._get_status(response) == INVALID_TOKEN:
            if self.token is None:
                return "No session token, login first"
            return "The token is invalid, try loging back in"

    def _check_token(self) -> bool:
        """Check whether the current session token, if it exists, is still valid.

        Returns:
            bool: True if the token is present and valid, False otherwise.

        Note:
            This is a legacy method, meant to test session tokens and not non-expiring
            API tokens. The API path is obsolete since version 9.0 of the server.
        """
        # TODO: deprecate this method.

        if not self.server_url.startswith("http"):
            log.warning(
                "Invalid server URL, it must begin with the protocol (HTTP/HTTPS)"
            )
            return False

        if self.token is None:
            return False

        # this API path is deprecated
        url = f"{self.server_url}/checkForUpdate"
        params = {"token": self.token}

        r = requests.get(url, params=params)

        if self._is_ok(r):
            return True
        else:
            log.debug(self._get_error_message(r))
            return False

    def _set_current_token(self, token: str) -> None:
        """Set this Connection's token.

        Args:
            token: The API token to use.
        """

        self.token = token
        self.params["token"] = token

    def _get(
        self, path: str, params: Dict[str, str] = dict(), stream=False
    ) -> requests.Response:
        """Perform the GET request.

        If a token is set, use it without checking whether it is valid. Otherwise,
        it means that the user has not logged in so an exception is raised.

        Args:
            path:
                The API path to GET. It is the last part of the URL, after '/api/'.
                For example, if the URL is https://<server address>/api/user/login,
                path corresponds to the 'user/login' part.
            params:
                The parameters to use. Defaults to an empty Dict. Normally, there is no
                need to include the token in these parameters, see note below.
            stream:
                It is passed as is to requests' get. Defaults to False.

        Returns:
            requests.Response: The response received.

        Raises:
            Exception: If the token is not set, i.e. the user has not logged in.

        Note:
            If the Connection has an API token, set either when it was created or by
            _auto_login, it is automatically added to the params. However, there may be
            cases where another API token or a session token must be used. To do so,
            simply include the token in the params dict and it will be used instead of
            the API token.
            If the Connection does not have an API token, then a token *must* be in the
            given params.
        """

        # Check if an API token is set or the user is using another token in params.
        if self.token is None and params.get("token", None) is None:
            log.error("You have to log in first")
            raise Exception("Must login before using _get")

        url = f"{self.server_url}/{path}"

        full_params = {**self.params, **params}

        return requests.get(url, params=full_params, stream=stream)

    def _auto_login(self) -> ConnectionResponse:
        """Reads the server URL and API token from the config file.

        If found, the API token is assumed to be valid.

        Returns:
            ConnectionResponse: With status and message.

            status:
                Can be INIT_ERROR, which indicates a configuration problem that may be
                solved by calling config.init_config.
            message:
                If an error occurred.
        """

        response = config.read_config()

        if response.is_ok():

            data: Tuple[str, str] = response.data
            server_url, api_token = data

            if not api_token:
                log.warning("No API token found in config file")
                return ConnectionResponse(
                    ERROR, "Can't auto-login without an API token"
                )

            self.server_url = server_url
            self._set_current_token(api_token)
            log.debug("API token found")

        else:

            error = "INIT_ERROR" if response.status == INIT_ERROR else "ERROR"
            log.debug(f"{error} when calling read_config")
            return ConnectionResponse(response.status, response.message)

    def _list_zones(self, path: str, domain: str, direction: str) -> ConnectionResponse:
        """General method to list zones.

        Args:
            path:
                The API path to use.
            domain:
                The domain name to list records of.
            direction:
                The direction on which to browse the zone, can be 'up' or 'down'.

        Returns:
            ConnectionResponse: With status, message and data.

            message:
                If an error occurred.
            data:
                If successful, data is the tuple (zones, records).
        """
        if direction not in ["up", "down"]:
            return ConnectionResponse(ERROR, f"Invalid direction {direction}")

        params = {"domain": domain, "direction": direction}

        r = self._get(path, params)

        if self._is_ok(r):
            resp = r.json().get("response")
            records = resp.get("records")
            zones = resp.get("zones")
            return ConnectionResponse(OK, data=(zones, records))

        else:
            log.debug(f"{path=}, {domain=}, {direction=}")
            log.debug(self._get_error_message(r))
            return ConnectionResponse(ERROR, "Could not list zones")

    def _delete_zone(self, path: str, domain: str) -> ConnectionResponse:
        """General method to delete a zone.

        Args:
            path:
                The API path to use.
            domain:
                The domain to delete.

        Returns:
            ConnectionResponse: With only status.
        """
        params = {"domain": domain}

        r = self._get(path, params)

        if self._is_ok(r):
            return ConnectionResponse(OK)
        else:
            log.debug(self._get_error_message(r))
            return ConnectionResponse(ERROR)

    def _flush(self, path: str) -> ConnectionResponse:
        """General method to flush a group of zones.

        Args:
            path: The API path to use.

        Returns:
            ConnectionResponse: With only status.
        """

        r = self._get(path)

        if self._is_ok(r):
            return ConnectionResponse(OK)
        else:
            log.debug(self._get_error_message(r))
            return ConnectionResponse(ERROR)

    ######################### User methods ##########################

    def login(self, username: str, password: str) -> ConnectionResponse:
        """Gets a new session token.

        Not to be confused with the new non-expiring API tokens, which can be generated
        with a session token.

        Args:
            username:
                The username. The server default is admin.
            password:
                The user's password. The server default is admin.

        Returns:
            ConnectionResponse: With status and message.

        Note:
            Session tokens expire 30 minutes after the last API call.
        """
        url = f"{self.server_url}/user/login"
        params = {"user": username, "pass": password}

        r = requests.get(url, params=params)

        if self._is_ok(r):
            self.session_token = r.json().get("token")
            return ConnectionResponse(OK, "Logged in")

        log.debug(self._get_error_message(r))
        return ConnectionResponse(ERROR, "Can't log in")

    def create_api_token(
        self, username: str, password: str, token_name: str, save: bool = True
    ) -> ConnectionResponse:
        """Creates a non-expiring API token.

        Introduced in version 9.0 of the server, they are the preferred method of
        authentication.

        Args:
            username:
                The username of the current user.
            password:
                The user's password.
            token_name:
                A name given to the token to identify it in the web UI.
            save:
                Whether to save the new token to the config file. Defaults to True.

        Returns:
            ConnectionResponse: With status and message.
        """

        params = {"user": username, "pass": password, "tokenName": token_name}

        r = self._get("user/createToken", params)

        if self._is_ok(r):

            token = r.json().get("token")
            self._set_current_token(token)

            if save:
                response = config.modify_config(self.server_url, self.token)
                if not response.is_ok():
                    log.debug(f"Error creating a new API token: {response.message}")
                    return ConnectionResponse(ERROR, response.message)

            return ConnectionResponse(OK, f"Created API token {token_name}")

        else:

            error = self._get_error_message(r)
            log.debug(f"Error creating new API token: {error}")
            return ConnectionResponse(
                ERROR, f"Could not create a new API token: {error}"
            )

    def logout(self) -> ConnectionResponse:
        """Disable the current session token.

        Return successfully even if no session token is set.

        Returns:
            ConnectionResponse: With status and message.
        """
        if not self.session_token:
            return ConnectionResponse(OK, "No session to close")

        # Set the token to session_token to override the API token in self.params.
        params = {"token": self.session_token}

        r = self._get("user/logout", params)

        if self._is_ok(r):
            self.session_token = ""
            return ConnectionResponse(OK, "Logged out")
        else:
            log.debug(self._get_error_message(r))
            return ConnectionResponse(ERROR, "Can't log out")

    def get_session_info(self) -> ConnectionResponse:
        """Gets the session information for the current token.

        Returns:
            ConnectionResponse: With status, message and data.

            message:
                If an error occurred.
            data:
                If successful, the session info, which is a Dict.
        """

        r = self._get("user/session/get")

        if self._is_ok(r):
            data = r.json().get("info")
            return ConnectionResponse(OK, data=data)
        else:
            log.debug(self._get_error_message(r))
            return ConnectionResponse(ERROR, "Could not get the session info")

    def delete_user_session(self, partial_token: str) -> ConnectionResponse:
        """Deletes the user session that corresponds to a partial token.

        Args:
            partial_token: The partial token included in a session from the
            user profile.

        Returns:
            ConnectionResponse: _description_
        """
        # Normally, the absence of a session token means the absence of a session.
        if not self.session_token:
            return ConnectionResponse(
                OK, "No session token found, assuming no session to close"
            )

        # Override the token since the session token is required, and not the API one.
        params = {"token": self.session_token, "partialToken": partial_token}

        r = self._get("user/session/delete", params)

        if self._is_ok(r):
            return ConnectionResponse(OK, "Deleted session")
        else:
            log.debug(self._get_error_message(r))
            return ConnectionResponse(ERROR, "Could not delete the session")

    def change_password(self, new_password: str) -> ConnectionResponse:
        """Change the user's password.

        Must be logged in with the login method to get a session token, since the
        password cannot be changed with an API token.

        Args:
            new_password: The new password to set.

        Returns:
            ConnectionResponse: With status and message.
        """
        if not self.session_token:
            return ConnectionResponse(
                ERROR, "Use login to be able to change the password"
            )

        params = {"pass": new_password}

        r = self._get("user/changePassword", params=params)

        if self._is_ok(r):
            return ConnectionResponse(OK, "Password changed")
        else:
            log.debug(self._get_error_message(r))
            return ConnectionResponse(ERROR, "Could not change password")

    def get_user_profile(self) -> ConnectionResponse:
        """Gets the user profile info.

        Returns:
            ConnectionResponse: With status, message and data.

            message:
                If an error occurred.
            data:
                If successful, the session info, which is a Dict.
        """

        r = self._get("user/profile/get")

        if self._is_ok(r):
            data = r.json().get("response")
            return ConnectionResponse(OK, data=data)
        else:
            log.debug(self._get_error_message(r))
            return ConnectionResponse(ERROR, "Could not get the user's profile")

    def set_user_profile(
        self, display_name: str = "", session_timeout: int = -1
    ) -> ConnectionResponse:
        """Sets some user profile values.

        Args:
            display_name:
                The user's display name. Defaults to "". It can be different than the
                user's username.
            session_timeout:
                The time in seconds before the user is timed out. Defaults to -1.
                Any negative value is ignored. 0 disables the timeout.

        Returns:
            ConnectionResponse: with status and message.
        """
        if not display_name and session_timeout < 0:
            return ConnectionResponse(OK, "No changes made")

        params = dict()
        if display_name:
            params["displayName"] = display_name
        if session_timeout >= 0:
            params["sessionTimeoutSeconds"] = session_timeout

        r = self._get("user/profile/set", params)

        if self._is_ok(r):
            return ConnectionResponse(OK, "Profile changes applied")
        else:
            log.debug(self._get_error_message(r))
            return ConnectionResponse(ERROR, "Could not change the user profile")

    def check_update(self) -> ConnectionResponse:
        """Check if a server update is available.

        Returns:
            ConnectionResponse: With status and message.

            message:
                If OK and an update is available, the message indicates the current
                version and the new version.
        """

        r = self._get("user/checkForUpdate")

        if self._is_ok(r):
            resp = r.json().get("response")
            if resp.get("updateAvailable"):
                old_ver = resp.get("currentVersion")
                new_ver = resp.get("updateVersion")
                return ConnectionResponse(
                    OK, f"Update from {old_ver} to {new_ver} available"
                )
            else:
                return ConnectionResponse(OK, "No update available")
        else:
            log.debug(self._get_error_message(r))
            return ConnectionResponse(ERROR, "Could not check for updates")

    ################################ Dashboard methods ################################

    def get_stats(
        self, timeframe: str, start: str = "", end: str = ""
    ) -> ConnectionResponse:
        """Gets the stats that are displayed on the web dashboard.

        Args:
            timeframe:
                The timeframe of the logs to retrieve. Can be "lastHour", "lastDay",
                "lastWeek", "lastMonth", "lastYear" or "custom".
            start:
                The start date in UTC. Defaults to "". Only if the timeframe is
                "custom".
            end:
                The end date in UTC. Defaults to "". Only if the timeframe is "custom".

        Returns:
            ConnectionResponse: with status, message and data.

            data:
                Only if OK.

        Note:
            This function is untested.
        """
        # TODO: test this function

        params = {"type": timeframe}

        if timeframe == "custom":
            if not start or not end:
                return ConnectionResponse(
                    ERROR, "Provide a start and end dates when using a custom timeframe"
                )
            else:
                params["start"] = start
                params["end"] = end
        elif timeframe not in [
            "lastHour",
            "lastDay",
            "lastWeek",
            "lastMonth",
            "lastYear",
        ]:
            return ConnectionError(ERROR, f"Invalid timeframe {timeframe}")

        r = self._get("dashboard/stats/get", params)

        if self._is_ok(r):
            data = r.json().get("response")
            return ConnectionResponse(OK, "Received stats from the server", data=data)
        else:
            log.debug(self._get_error_message(r))
            return ConnectionResponse(ERROR, "Could not get stats from the server")

    def get_top_stats(
        self, stats_type: str, timeframe: str = "lastHour", limit: int = 1000
    ) -> ConnectionResponse:
        """Gets the top stats.

        Args:
            stats_type:
                The type of stats. Can be "TopClients", "TopDomains" or
                "TopBlockedDomains".
            timeframe:
                The timeframe of the logs to retrieve. Can be "lastHour", "lastDay",
                "lastWeek", "lastMonth" or "lastYear".
            limit:
                The maximum number of records to retrieve. Defaults to 1000.

        Returns:
            ConnectionResponse: with status, message and data.

            data:
                Only if OK.

        Note:
            This function is untested.
        """
        # TODO: test this function

        if timeframe not in [
            "lastHour",
            "lastDay",
            "lastWeek",
            "lastMonth",
            "lastYear",
        ]:
            return ConnectionResponse(ERROR, f"Invalid timeframe {timeframe}")

        if stats_type not in ["TopClients", "TopDomains", "TopBlockedDomains"]:
            return ConnectionResponse(ERROR, f"Invalid stats_type {stats_type}")

        if limit < 1:
            return ConnectionResponse(ERROR, "Limit must be positive")

        params = {"type": timeframe, "statsType": stats_type, "limit": limit}

        r = self._get("dashboard/stats/getTop", params)

        if self._is_ok(r):
            data = r.json().get("response")
            return ConnectionResponse(OK, "Received top stats", data=data)
        else:
            log.debug(self._get_error_message(r))
            return ConnectionError(ERROR, "Could not get top stats from the server")

    def delete_stats(self) -> ConnectionError:
        """Delete all stats from disk and from memory.

        Returns:
            ConnectionError: with status and message.
        """

        r = self._get("dashboard/stats/deleteAll")

        if self._is_ok(r):
            return ConnectionResponse(OK, "Deleted all stats")
        else:
            log.debug(self._get_error_message(r))
            return ConnectionResponse(ERROR, "Could not delete stats")

    ########################### Authoritative zone methods ###########################

    def list_zones(self) -> ConnectionResponse:
        """List all authoritative zones hosted on the server

        Returns:
            ConnectionResponse: with status, message and data.

            message:
                If an error occurred.
            data:
                If OK, the list of all zones as returned by the server, i.e. a list of
                dicts, see https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md#authoritative-zone-api-calls  # noqa
        """

        r = self._get("zones/list")

        if self._is_ok(r):
            data = r.json().get("response")
            zones = data.get("zones")
            return ConnectionResponse(OK, zones)
        else:
            log.debug(self._get_error_message(r))
            return ConnectionResponse(
                ERROR, "Could not get list of authoritative zones"
            )

    def create_zone(
        self,
        zone: str,
        zone_type: str = "primary",
        primary_ns: str = "",
        sec_zone_transfer_protocol: str = "tcp",
        sec_zone_tsig_key_name: str = "",
        fwd_zone_forwarder_protocol: str = "Udp",
        fwd_zone_forwarder: str = "",
        fwd_zone_dnssec_validation: bool = False,
    ) -> ConnectionResponse:
        """Create a new primary, secondary, stub or conditionnal forwarder zone

        Args:
            zone:
                The domain name of the zone to add. Can be a valid domain name, an IP
                address or a network address in CIDR notation. Providing an IP or
                network address creates a reverse zone.
            zone_type:
                The type of zone to create. Can be primary, secondary, stub or
                forwarder.
            sec_zone_primary_ns:
                List of comma separated IP addresses of the primary
                name server, used by Secondary or Stub zones. Can be omitted,
                in which case the primary name server is resolved recursively.
            sec_zone_transfer_protocol:
                The zone transfer protocol used by secondary zones. Can be tcp or tls.
                Defaults to tcp.
            sec_zone_tsig_key_name:
                Name of the TSIG key used by secondary zones.
            fwd_zone_forwarder_protocol:
                The DNS transport protocol used by a Conditional Forwarder zone. Can be
                Udp, Tcp, Tls or Https. Defaults to Udp.
            fwd_zone_forwarder:
                Address of the DNS server used as a forwarder by a Forwarder zone.
                Defaults to `this-server`, which allows you to override the zone with
                records. If a record is not overriden it is then resolved via the
                server as all other queries.
            fwd_zone_dnssec_validation:
                Whether to enable DNSSEC validation for a Forwarder zone. Defaults to
                False.

        Returns:
            ConnectionResponse: with status, message.

        Notes:
            - Currently options related to a proxy are missing.
            - Options related to secondary zones are untested.
        """
        # TODO: add proxy options

        params = {"zone": zone, "type": zone_type}

        if zone_type == "primary":
            # just need to send the zone and type
            pass

        elif zone_type == "secondary":
            if primary_ns:
                params["primaryNameServerAddresses"] = primary_ns
            if sec_zone_tsig_key_name:
                params["tsigKeyName"] = sec_zone_tsig_key_name
            # has a default
            params["zoneTransferProtocol"] = sec_zone_transfer_protocol

        elif zone_type == "forwarder":
            if fwd_zone_forwarder:
                params["forwarder"] = fwd_zone_forwarder
            else:
                return ConnectionResponse(
                    ERROR,
                    "Must use a forwarder when creating a Conditional Forwarder zone",
                )
            params["protocol"] = fwd_zone_forwarder_protocol
            params["dnssecValidation"] = fwd_zone_dnssec_validation

        elif zone_type == "stub":
            if primary_ns:
                params["primaryNameServerAddresses"] = primary_ns

        else:
            return ConnectionResponse(
                ERROR, "Zone type must be either primary, secondary, forwarder or stub"
            )

        r = self._get("zones/create", params=params)

        if self._is_ok(r):
            # getting domain from the response may be inefficient compared to just
            # using the given zone but since the server returns it we use it
            return ConnectionResponse(
                OK, f"Created {zone_type} zone {r.json().get('response').get('domain')}"
            )
        else:
            log.debug(self._get_error_message(r))
            return ConnectionResponse(ERROR, f"Failed to create zone {zone}")

    def enable_zone(self, zone: str) -> ConnectionResponse:
        """Enable an authoritative zone.

        Args:
            zone: Zone to enable.

        Returns:
            ConnectionResponse: with status and message.
        """

        params = {"zone": zone}
        r = self._get("zones/enable", params=params)

        if self._is_ok(r):
            return ConnectionResponse(OK, f"Enabled zone {zone}")
        else:
            log.debug(self._get_error_message(r))
            return ConnectionResponse(ERROR, f"Could not enable zone {zone}")

    def disable_zone(self, zone: str) -> ConnectionResponse:
        """Disable an authoritative zone.

        Args:
            zone: Zone to disable.

        Returns:
            ConnectionResponse: with status and message.
        """

        params = {"zone": zone}
        r = self._get("zones/disable", params=params)

        if self._is_ok(r):
            return ConnectionResponse(OK, f"Disabled zone {zone}")
        else:
            log.debug(self._get_error_message(r))
            return ConnectionResponse(ERROR, f"Could not disable zone {zone}")

    def delete_zone(self, zone: str):
        """Delete an authoritative zone

        Args:
            zone (str): The zone to delete
        """

        return self._delete_zone("zones/delete", zone)

    def resync_zone(self, zone: str) -> ConnectionResponse:
        """Resyncs a secondary or stub zone.

        Args:
            zone: The zone to resync.

        Returns:
            ConnectionResponse: with status and message.

        Note:
            This function is untested.
        """
        # TODO: test this function

        params = {"zone": zone}
        r = self._get("zones/resync", params=params)

        if self._is_ok(r):
            return ConnectionResponse(OK, f"Resynced zone {zone}")
        else:
            log.debug(self._get_error_message(r))
            return ConnectionResponse(ERROR, f"Could not resync zone {zone}")

    def get_zone_options(
        self, zone: str, include_tsig_names: bool = False
    ) -> ConnectionResponse:
        """Gets the options of a specific zone.

        Args:
            zone:
                The zone from which to read the options.
            include_tsig_names:
                Whether to include a list of the names of the available TSIG keys.
                Defaults to False.

        Returns:
            ConnectionResponse: with status, message and data.

            data:
                Only if OK.
        """

        params = {"zone": zone, "includeAvailableTsigKeyNames": include_tsig_names}
        r = self._get("zones/options/get", params=params)

        if self._is_ok(r):
            data = r.json().get("response")
            return ConnectionResponse(OK, f"Options from {zone}", data=data)
        else:
            log.debug(self._get_error_message(r))
            return ConnectionResponse(ERROR, f"Could not options for zone {zone}")

    def set_zone_options(self) -> ConnectionResponse:
        raise NotImplementedError

    def get_zone_permissions(
        self, zone: str, include_users_and_groups: bool = False
    ) -> ConnectionResponse:
        """Gets the permissions for a specific zone.

        Args:
            zone:
                The zone from which to read the options.
            include_users_and_groups:
                Whether to include a list of the users and groups. Defaults to False.

        Returns:
            ConnectionResponse: with status, message and data.

            data:
                Only if OK.
        """

        params = {"zone": zone, "includeUsersAndGroups": include_users_and_groups}
        r = self._get("zones/permissions/get", params=params)

        if self._is_ok(r):
            data = r.json().get("response")
            return ConnectionResponse(OK, f"Permissions for {zone}", data=data)
        else:
            log.debug(self._get_error_message(r))
            return ConnectionResponse(ERROR, f"Could not permissions for zone {zone}")

    def set_zone_permissions(self) -> ConnectionResponse:
        raise NotImplementedError

    def sign_zone(
        self,
        zone: str,
        algorithm: str = "ECDSA",
        rsa_hash: str = "SHA256",
        rsa_key_signing_key_size: int = 2048,
        rsa_zone_signing_key_size: int = 1024,
        ecdsa_curve: str = "P256",
        ttl: int = 3600,
        rsa_zone_signing_key_rollover: int = 90,
        nx_proof: str = "NSEC",
        nsec3_iterations: int = 0,
        nsec3_salt_length: int = 0,
    ) -> ConnectionResponse:
        """Signs a primary zone with DNSSEC.

        Args:
            zone:
                The primary zone to sign.
            algorithm:
                The algorithm to use. Can be ECDSA or RSA. Defaults to ECDSA.
            rsa_hash:
                The hash algorithm to use when using RSA. Can be MD5, SHA1, SHA256 or
                SHA512. Defaults to SHA256.
            rsa_key_signing_key_size:
                The size of the Key Signing Key. Required when using RSA, must be a
                positive value. Defaults to 2048.
            rsa_zone_signing_key_size:
                The size of the Zone Signing Key. Required when using RSA, must be a
                positive value. Defaults to 1024.
            ecdsa_curve:
                The name of the curve to use with ECDSA. Can be P256 or P384. Defaults
                to P256.
            ttl:
                The Time to Live for DNSKEY records. Defaults to 3600.
            rsa_zone_signing_key_rollover:
                The frequency in days at which the DNS server must rollover the Zone
                Signing Keys. Ranges from 0 to 365, 0 disables rollover. Defaults to 0.
            nx_proof:
                The type of proof of non-existence. Can be NSEC or NSEC3. Defaults to
                NSEC.
            nsec3_iterations:
                The number of iterations for hashing when using NSEC3. Defaults to 0.
            nsec3_salt_length:
                The length in bytes of the salt used with NSEC3. Defaults to 0.

        Note:
            The defaults are the same as those on the web console.
        """

        params = {
            "zone": zone,
            "algorithm": algorithm,
            "dnsKeyTtl": ttl,
            "nxProof": nx_proof,
        }

        # TODO: add validation of parameters?

        if algorithm == "ECDSA":
            params["curve"] = ecdsa_curve
        elif algorithm == "RSA":
            params["hash"] = rsa_hash
            params["kskKeySize"] = rsa_key_signing_key_size
            params["zskKeySize"] = rsa_zone_signing_key_size
            params["zskRolloverDays"] = rsa_zone_signing_key_rollover
        else:
            return ConnectionResponse(ERROR, "Algorithm must be either ECDSA or RSA")

        if nx_proof == "NSEC3":
            params["iterations"] = nsec3_iterations
            params["saltLength"] = nsec3_salt_length

        r = self._get("zones/dnssec/sign", params=params)

        if self._is_ok(r):
            return ConnectionResponse(OK, f"Signed zone {zone}")
        else:
            log.debug(self._get_error_message(r))
            return ConnectionResponse(ERROR, f"Could not sign zone {zone}")

    def unsign_zone(self, zone: str) -> ConnectionResponse:
        """Unsign a primary zone.

        Args:
            zone (str): The zone to unsign.

        Returns:
            ConnectionResponse: with status and message.

        Note:
            The web console displays some warnings when trying to unsign a zone while
            this wrapper does not.
        """

        params = {"zone": zone}

        r = self._get("zones/dnssec/unsign", params)

        if self._is_ok(r):
            return ConnectionResponse(OK, f"Unsigned zone {zone}")
        else:
            log.debug(self._get_error_message(r))
            return ConnectionResponse(ERROR, f"Could not unsign zone {zone}")
