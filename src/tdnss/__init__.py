# Copyright: (c) 2022, JulioLoayzaM
# GPL-3.0-only (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import logging

__version__ = "0.1.0"

# Create the logger with a Null handler, to leave the logging configuration to the user.
logging.getLogger(__name__).addHandler(logging.NullHandler())

# Define the status codes. Includes the three possible codes returned by the API and
# any custom code used to convey additional context.
(OK, ERROR, INVALID_TOKEN, INIT_ERROR) = range(4)
