#!/usr/bin/env python3
"""
WiFi Machine-in-the-Middle package

Automation of MitM Attack on WiFi Networks
Bachelor's Thesis UIFS FIT VUT
Martin Vondracek
2016
"""

import logging

__all__ = ['access', 'capture', 'common', 'model', 'topology', 'updatableProcess', 'wep', 'wpa2']

# Set default logging handler to avoid "No handler found" warnings.
logging.getLogger(__name__).addHandler(logging.NullHandler())
