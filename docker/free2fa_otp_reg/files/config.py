# config.py
# Copyright (C) 2024 Voloskov Aleksandr Nikolaevich

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# pylint: disable=too-few-public-methods

""" A module containing configuration parameters for an application. """

import os


class Config:
    """ A container class for storing configuration parameters. """
    #  Maximum number of unsuccessful password entries
    MAX_LOGIN_ATTEMPTS = int(os.environ.get("MAX_LOGIN_ATTEMPTS", 3))
    #  Lockout duration in minutes
    BLOCK_DURATION_MINUTES = int(os.environ.get("BLOCK_DURATION_MINUTES", 5))
    # Language of interface (ru or en)
    LANGUAGE = os.environ.get("FREE2FA_TELEGRAM_BOT_LANGUAGE", "ru")
    # How many seconds are given to respond
    # must also change the settings on the side of windows server
    # specifying the response timeout response radius server that FREE2FA_TIMEOUT +1 (21)
    FREE2FA_TIMEOUT = int(os.environ.get("FREE2FA_TIMEOUT", 20))
    # OTP Company Information for user
    OTP_FIRM_INFO = os.getenv("OTP_FIRM_INFO")
    # Secret for OTP radius
    OTP_RADIUS_SECRET = os.getenv("OTP_RADIUS_SECRET")
    # OTP RADIUS Port
    OTP_RADIUS_PORT = int(os.environ.get("OTP_RADIUS_PORT", 1822))
    # Session lifetime (10 minutes)
    SESSION_LIFETIME = int(os.environ.get("SESSION_LIFETIME", 10))
    