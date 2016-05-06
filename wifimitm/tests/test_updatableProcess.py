#!/usr/bin/env python3
"""
Unit tests for UpdatableProcess class

Automation of MitM Attack on WiFi Networks
Bachelor's Thesis UIFS FIT VUT
Martin Vondracek
2016
"""
import typing as _typing
import unittest as _unittest

from wifimitm.updatableProcess import UpdatableProcess


class TestUpdatableProcess(_unittest.TestCase):
    def __init__(self, methodName='runTest'):
        super().__init__(methodName)
        self.process = None  # type: _typing.Optional[UpdatableProcess]

    @classmethod
    def setUpClass(cls):
        # logging.basicConfig(format='[%(asctime)s] %(funcName)s: %(message)s', level=logging.DEBUG)
        # logging.captureWarnings(True)
        # warnings.simplefilter('always', ResourceWarning)
        cls.continuously_running_cmd = ['ping', '127.0.0.1']

    def tearDown(self):
        if self.process and issubclass(type(self.process), UpdatableProcess):
            self.process.cleanup()
            del self.process

    class UpdatableProcessSubclass(UpdatableProcess):
        def update(self):
            super().update()

    def test_abc(self):
        with self.assertRaisesRegex(TypeError, "Can't instantiate abstract class UpdatableProcess"):
            self.process = UpdatableProcess(self.continuously_running_cmd)

    def test_update(self):
        self.process = self.UpdatableProcessSubclass(self.continuously_running_cmd)
        self.process.cleanup()
        with self.assertRaisesRegex(ValueError, "Can't call update on process after cleanup was performed."):
            self.process.update()

    def test_stop1(self):
        self.process = self.UpdatableProcessSubclass(self.continuously_running_cmd)
        self.process.stop()
        self.assertIsNotNone(self.process.poll(), 'Process did not stopped on stop.')

    def test_stop2(self):
        self.process = self.UpdatableProcessSubclass(self.continuously_running_cmd)
        self.process.cleanup()
        with self.assertRaisesRegex(ValueError, "Can't call stop on process after cleanup was performed."):
            self.process.stop()

    def test_cleanup(self):
        self.process = self.UpdatableProcessSubclass(self.continuously_running_cmd)
        self.process.cleanup()

        self.assertIsNotNone(self.process.poll(), 'Process did not stopped on cleanup.')
        self.assertFalse(self.process._finalizer.alive)
        self.assertIsNone(self.process.stdout)
        self.assertTrue(self.process.stdout_r.closed)
        self.assertTrue(self.process.stdout_w.closed)
        self.assertIsNone(self.process.stderr)
        self.assertTrue(self.process.stderr_r.closed)
        self.assertTrue(self.process.stderr_w.closed)
        self.assertTrue(self.process.cleaned)

    def test___enter__(self):
        with self.UpdatableProcessSubclass(self.continuously_running_cmd) as self.process:
            self.assertIsNone(self.process.poll(), 'Process did not started on __enter__.')
            self.process.stop()

    def test___exit__(self):
        with self.UpdatableProcessSubclass(self.continuously_running_cmd) as self.process:
            self.process.stop()
        self.assertIsNotNone(self.process.poll(), 'Process did not stopped on __exit__.')
        self.assertTrue(self.process.cleaned, 'Process did not clean on __exit__.')

    def test__del__1(self):
        with self.assertWarnsRegex(ResourceWarning,
                                   'Process {} was not stopped correctly. Stopping it by destructor, which is not'
                                   ' always safe!'.format(self.UpdatableProcessSubclass.__name__)):
            self.process = self.UpdatableProcessSubclass(self.continuously_running_cmd)
            self.process = 'replacement'

    def test__del__2(self):
        with self.assertWarnsRegex(ResourceWarning,
                                   'Process {} was not stopped correctly. Stopping it by destructor, which is not'
                                   ' always safe!'.format(self.UpdatableProcessSubclass.__name__)):
            self.process = self.UpdatableProcessSubclass(self.continuously_running_cmd)
            del self.process
            self.process = None
