# Copyright: (c) 2022, JulioLoayzaM
# GPL-3.0-only (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import logging


class CustomFormatter(logging.Formatter):
    """A custom Formatter for pretty printing."""

    # Some colors for better visibility
    RED = "\033[91m"
    YELLOW = "\033[93m"
    ENDC = "\033[0m"

    FORMATS = {
        logging.DEBUG: "[%(funcName)s] %(message)s (%(module)s:%(funcName)s:%(lineno)d)",  # noqa
        logging.INFO: "[%(funcName)s] %(message)s",
        logging.WARNING: f"[%(funcName)s] {YELLOW}Warning: %(message)s{ENDC}",
        logging.ERROR: f"[%(funcName)s] {RED}Error: %(message)s{ENDC}",
        logging.CRITICAL: f"[%(funcName)s] {RED}CRITICAL: %(message)s{ENDC}",
    }

    def format(self, record: logging.LogRecord):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)
