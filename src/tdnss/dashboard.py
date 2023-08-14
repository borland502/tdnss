"""Module for dashboard API calls."""

import logging

from tdnss import OK, ERROR
from tdnss.baseresponse import BaseResponse
from tdnss.connection import Connection

log = logging.getLogger(__name__)


class DashboardResponse(BaseResponse):
    pass


class DashboardAPI:
    """Dashboard API calls.

    Args:
        connection:
            The :class:`tdnss.connection.Connection` to use.
    """

    def __init__(self, connection: Connection):
        self.connection = connection

    def get_stats(
        self, timeframe: str = "LastHour", start: str = "", end: str = ""
    ) -> DashboardResponse:
        """Gets the stats that are displayed on the web dashboard.

        Args:
            timeframe:
                The timeframe of the logs to retrieve. Can be "LastHour",
                "LastDay", "LastWeek", "LastMonth", "LastYear" or "custom".
            start:
                The start date in UTC, only used if the timeframe is "custom".
            end:
                The end date in UTC, only used if the timeframe is "custom".

        Returns:
            DashboardResponse: with status, message and data.

            data:
                Only if OK.
        """
        params = {"type": timeframe}

        if timeframe == "custom":
            if not start or not end:
                return DashboardResponse(
                    ERROR, "Provide a start and end dates when using a custom timeframe"
                )
            else:
                params["start"] = start
                params["end"] = end
        elif timeframe not in [
            "LastHour",
            "LastDay",
            "LastWeek",
            "LastMonth",
            "LastYear",
        ]:
            return DashboardResponse(ERROR, f"Invalid timeframe {timeframe}")

        r = self.connection._get("dashboard/stats/get", params)

        if self.connection._is_ok(r):
            data = r.json().get("response")
            return DashboardResponse(OK, "Received stats from the server", data=data)
        else:
            log.debug(self.connection._get_error_message(r))
            return DashboardResponse(ERROR, "Could not get stats from the server")

    def get_top_stats(
        self, stats_type: str, timeframe: str = "LastHour", limit: int = 1000
    ) -> DashboardResponse:
        """Gets the top stats.

        Args:
            stats_type:
                The type of stats. Can be "TopClients", "TopDomains" or
                "TopBlockedDomains".
            timeframe:
                The timeframe of the logs to retrieve. Can be "LastHour", "LastDay",
                "LastWeek", "LastMonth" or "LastYear".
            limit:
                The maximum number of records to retrieve. Defaults to 1000.

        Returns:
            DashboardResponse: with status, message and data.

            data:
                Only if OK.
        """
        if timeframe not in [
            "LastHour",
            "LastDay",
            "LastWeek",
            "LastMonth",
            "LastYear",
        ]:
            return DashboardResponse(ERROR, f"Invalid timeframe {timeframe}")

        if stats_type not in ["TopClients", "TopDomains", "TopBlockedDomains"]:
            return DashboardResponse(ERROR, f"Invalid stats_type {stats_type}")

        if limit < 1:
            return DashboardResponse(ERROR, "Limit must be positive")

        params = {"type": timeframe, "statsType": stats_type, "limit": limit}

        r = self.connection._get("dashboard/stats/getTop", params)

        if self.connection._is_ok(r):
            data = r.json().get("response")
            return DashboardResponse(OK, "Received top stats", data=data)
        else:
            log.debug(self._get_error_message(r))
            return DashboardResponse(ERROR, "Could not get top stats from the server")

    def delete_stats(self) -> DashboardResponse:
        """Delete all stats from disk and from memory.

        Returns:
            ConnectionError: with status and message.
        """

        r = self.connection._get("dashboard/stats/deleteAll")

        if self.connection._is_ok(r):
            return DashboardResponse(OK, "Deleted all stats")
        else:
            log.debug(self._get_error_message(r))
            return DashboardResponse(ERROR, "Could not delete stats")
