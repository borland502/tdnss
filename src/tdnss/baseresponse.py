# Copyright: (c) 2022, JulioLoayzaM
# GPL-3.0-only (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from dataclasses import dataclass
from typing import Any

from tdnss import OK


@dataclass
class BaseResponse:
    """The base class for responses.

    These responses are a way of returning information to the user of this wrapper in a
    standard format across the modules. They consist of three fields:
        - a status, which may be one of the three possible statuses returned by the
          API (ok, error or invalid-token);
        - an optional message to the user, if something should be displayed to the user
          e.g. an error occurred, return the reason so it can be printed;
        - and any data returned by the API call, if applicable.

    When returning a Response, the docstring should indicate which fields are being
    used, and if any conditions apply. If no additional conditions are given for an
    included field, a default behaviour is implied.

    For example:

        Returns:
            BaseResponse: with status, message and data.

            message:
                If an error occurred.
            data:
                The server information, if successful.

    We see that status does not have a description, so we assume it can only be one of
    the three base statuses. However a message is returned only if an error occurred,
    so this behaviour is documented. Same goes for data, which is only returned is the
    request was successful, i.e. status == OK.
    """

    status: int
    message: str = ""
    data: Any = None

    def is_ok(self) -> bool:
        """A quick way of checking if the request was successful.

        Returns:
            bool: True if status is OK, False otherwise.
        """
        return self.status == OK
