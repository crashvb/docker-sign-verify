#!/usr/bin/env python

# pylint: disable=too-few-public-methods

"""Reusable string literals."""

from enum import Enum


class SignatureTypes(Enum):
    """
    Docker signature types.
    """

    SIGN = 0  # Append (Co-)signature
    ENDORSE = 1  # Append endorsement
    RESIGN = 2  # Replace signature(s)
