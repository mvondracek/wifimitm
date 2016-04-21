#!/usr/bin/env python3
"""
Unit tests for capture module

Automatization of MitM Attack on WiFi Networks
Bachelor's Thesis UIFS FIT VUT
Martin Vondracek
2016
"""
import time as _time
import typing as _typing
import unittest as _unittest

from wifimitm.updatableProcess import UpdatableProcess
from wifimitm.capture import Dumpcap
from wifimitm.model import WirelessInterface as _WirelessInterface

__author__ = 'Martin Vondracek'
__email__ = 'xvondr20@stud.fit.vutbr.cz'


class TestDumpcap(_unittest.TestCase):
    def __init__(self, methodName='runTest'):
        super().__init__(methodName)
        self.process = None  # type: _typing.Optional[Dumpcap]

    @classmethod
    def setUpClass(cls):
        cls.network_interface_name = 'wlp1s0'  # type: str
        cls.network_interface_obj = _WirelessInterface(cls.network_interface_name)  # type: _WirelessInterface

    def tearDown(self):
        if self.process and issubclass(type(self.process), UpdatableProcess):
            self.process.cleanup()
            del self.process

    def test__init__1(self):
        with self.assertRaisesRegex(ValueError, 'You must specify a valid interface name.'):
            self.process = Dumpcap('invalid network interface name')

    def test__init__2(self):
        self.process = Dumpcap(self.network_interface_name)

    def test__init__3(self):
        self.process = Dumpcap(self.network_interface_obj)

    def test_update(self):
        with Dumpcap(self.network_interface_obj) as self.process:
            self.assertEqual(self.process.state, type(self.process).State.STARTED)
            _time.sleep(1)  # some time for dumpcap to generate some output
            self.process.update()
            self.assertNotEqual(self.process.state, type(self.process).State.STARTED)
            self.process.stop()
            self.assertEqual(self.process.state, type(self.process).State.TERMINATED)
