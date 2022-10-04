# Copyright: (c) 2022, JulioLoayzaM
# GPL-3.0-only (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
This module generates the configuration file for tdnss.

This file is created inside $HOME/.config/tdnss.
"""

import configparser
import logging

from dataclasses import dataclass
from pathlib import Path

from tdnss import OK, ERROR, INIT_ERROR
from tdnss.baseresponse import BaseResponse


CONFIG_DIR_PATH = Path.home() / ".config" / "tdnss"
CONFIG_FILE_PATH = CONFIG_DIR_PATH / "config.ini"

log = logging.getLogger(__name__)


@dataclass
class ConfigResponse(BaseResponse):
    """A response from the configuration module.

    ConfigResponse may use the custom INIT_ERROR status code to indicate that an error
    occurred but it (probably) can be solved by calling init_config. As such, users
    should look out for this status when calling read_config and modify_config.
    """


def init_config(server_url: str, api_token: str = "") -> ConfigResponse:
    """Initializes the configuration file.

    Args:
        server_url:
            The server's URL, including the protocol (e.g HTTPS). As all API URLs are
            of the form 'https://<server address>/api/<api path>', we append the '/api'
            portion before saving the URL to the file.
        api_token:
            A non-expiring API token. The token's validity is not checked before saving.

    Returns:
        ConfigResponse: With status and message.
    """

    try:
        CONFIG_DIR_PATH.mkdir(mode=0o700, exist_ok=True)
    except Exception as error:
        log.debug(error)
        return ConfigResponse(ERROR, "Error creating the configuration directory")

    try:
        CONFIG_FILE_PATH.touch(mode=0o600, exist_ok=True)
    except Exception as error:
        log.debug(error)
        return ConfigResponse(ERROR, "Error creating the configuration file")

    if not server_url.startswith("http"):
        return ConfigResponse(
            ERROR,
            (
                "Please specify the protocol (HTTP/HTTPS), for example: "
                "http://localhost:5380"
            ),
        )

    # the url should be in the form http://<server address>/api
    if not server_url.endswith("/api"):
        if server_url[-1] != "/":
            server_url += "/"
        server_url += "api"

    config_parser = configparser.ConfigParser()
    config_parser["General"] = {"server_url": server_url}

    if api_token:
        config_parser["General"]["api_token"] = api_token

    try:
        with CONFIG_FILE_PATH.open("w") as file:
            config_parser.write(file)
    except Exception as error:
        log.debug(error)
        return ConfigResponse(ERROR, "Error writing to the configuration file")

    return ConfigResponse(OK, f"Created {str(CONFIG_FILE_PATH)}")


def read_config() -> ConfigResponse:
    """Reads the config file.

    Returns:
        ConfigResponse: With status, message and data.

        status:
            Can be INIT_ERROR, which indicates an error that can probably be
            solved by calling init_config.
        message:
            Only if an error occurred.
        data:
            If successful, the returned data is a tuple containing the server_url and
            an api_token. api_token may be an empty string if the user did not provide
            one when calling init_config and has never logged on (successfully).
    """

    if not CONFIG_FILE_PATH.exists():
        return ConfigResponse(INIT_ERROR, "The config file does not exist")

    config = configparser.ConfigParser()

    try:
        with CONFIG_FILE_PATH.open("r") as file:
            config.read_file(file)
    except Exception as error:
        log.debug(error)
        return ConfigResponse(ERROR, "Could not open config file")

    try:
        general = config["General"]
        server_url = general["server_url"]
    except KeyError:
        return ConfigResponse(INIT_ERROR, "The configuration file is empty or invalid")

    # the token may not exist, so we use get
    api_token = general.get("api_token", "")

    return ConfigResponse(OK, data=(server_url, api_token))


def modify_config(
    server_url: str = "",
    api_token: str = "",
) -> ConfigResponse:
    """Updates the config file.

    Args:
        server_url:
            The new server_url. Defaults to "".
        api_token:
            The new api_token. Defaults to "". The token's validity is not checked
            before saving.

    Returns:
        ConnectionResponse: With status and message.
    """

    if not CONFIG_FILE_PATH.exists():
        return ConfigResponse(INIT_ERROR, "The configuration file does not exist")

    if not (server_url or api_token):
        return ConfigResponse(OK, "Nothing to update")

    config = configparser.ConfigParser()

    try:
        with CONFIG_FILE_PATH.open("r") as file:
            config.read_file(file)
    except Exception as error:
        log.debug(error)
        return ConfigResponse(ERROR, "Could not open the config file")

    res = "Successfully updated "
    items = list()

    if server_url:
        config["General"]["server_url"] = server_url
        items.append("server_url")
    if api_token:
        config["General"]["api_token"] = api_token
        items.append("api_token")

    res += ", ".join(items)

    try:
        with CONFIG_FILE_PATH.open("w") as file:
            config.write(file)
    except Exception as error:
        log.debug(error)
        return ConfigResponse(ERROR, "Could not write to config file")

    return ConfigResponse(OK, res)
