#!/usr/bin/env python3
"""
Capturing network traffic

Automation of MitM Attack on WiFi Networks
Bachelor's Thesis UIFS FIT VUT
Martin Vondracek
2016

#Implementation notes
- When dumpcap is run as root, it is able to write the capture file only to destinations which the root owns. Generated
  capture file is therefore written to /tmp/ location and can be later copied out.
  https://bugs.launchpad.net/ubuntu/+source/wireshark/+bug/389467
- Dumpcap writes output to stderr, it's stdout is empty.

"""
import logging
import re
from enum import Enum, unique
from typing import Dict, Optional, BinaryIO

from .updatableProcess import UpdatableProcess
from .model import WirelessInterface

__author__ = 'Martin Vondracek'
__email__ = 'xvondr20@stud.fit.vutbr.cz'

logger = logging.getLogger(__name__)


class Dumpcap(UpdatableProcess):
    """
    "dumpcap - Dump network traffic
    Dumpcap is a network traffic dump tool. It lets you capture packet data from a live network and write the packets
    to a file. Dumpcap's default capture file format is pcap-ng format.
    Without any options set it will use the libpcap/WinPcap library to capture traffic from the first available network
    interface and writes the received raw packet data, along with the packets' time stamps into a pcap file.
    If the -w option is not specified, Dumpcap writes to a newly created pcap file with a randomly chosen name.
    Packet capturing is performed with the pcap library. The capture filter syntax follows the rules of
    the pcap library."
    `dumpcap\ -\ The\ Wireshark\ Network\ Analyzer\ 2.0.0 <https://www.wireshark.org/docs/man-pages/dumpcap.html>`_
    """
    # compiled regular expressions
    CRE_CAP_FILE_PATH = re.compile(r'File: (?P<cap_file_path>\S+)')
    CRE_PACKETS = re.compile(r'Packets: (?P<packets>\d+) ')  # space after number
    CRE_SUMMARY1 = re.compile(r'Packets captured: \d+')  # no space after number
    CRE_SUMMARY2 = re.compile(
        r"Packets received/dropped on interface '\S+':"
        r" (?P<received>\d+)/(?P<dropped>\d+) \(pcap:\d+/dumpcap:\d+/flushed:\d+/ps_ifdrop:\d+\) \(\d+\.\d+%\)"
    )
    CRE_NETWORK_DISCONNECTED = re.compile(
        r'dumpcap: The network adapter on which the capture was being done is no longer running;'
        r' the capture has stopped.')

    @unique
    class State(Enum):
        """
        Dumpcap process states.
        """
        CAPTURING = 0
        """Capturing and some packets have already been captured."""
        STARTED = 2
        """Process just started."""
        AWAITING_PACKETS = 3
        """Capture started, but no packets have been received yet."""
        STOPPING = 4
        """Printing capture summary."""
        TERMINATED = 100
        """Process have been terminated. By self.stop() call, on its own or by someone else."""

    def __init__(self, interface: WirelessInterface, capture_file: Optional[BinaryIO] = None):
        """
        :type capture_file: Optional[BinaryIO]
        :param capture_file: file for writing packet capture

        :type interface: WirelessInterface
        :param interface: wireless interface for capture
        """
        self.state = self.State.STARTED
        self.flags = self.__initial_flags()
        self.stats = self.__initial_stats()

        self.interface = interface  # type: WirelessInterface
        self.capture_file = capture_file
        # If `capture_file` was None, dumpcap will create capture file in /tmp. `self.tmp_capture_file_path` is set
        # during `self.update`.
        self.tmp_capture_file_path = None

        cmd = ['dumpcap',
               '-i', self.interface.name]
        stdout = None
        if self.capture_file:
            # If `capture_file` was provided, set dumpcap to write raw packet data to stdout...
            cmd.append('-w')
            cmd.append('-')
            # ... and redirect dumpcap's stdout to provided `capture_file`.
            stdout = self.capture_file
        super().__init__(cmd, stdout=stdout)

    def __str__(self):
        return '<{!s} state={!s}, flags={!s}, stats={!s}>'.format(
            type(self).__name__, self.state, self.flags, self.stats)

    @staticmethod
    def __initial_stats() -> Dict[str, int]:
        """
        Return initial stats object describing state of the running process.
        :rtype: Dict[str,int]
        """
        stats = {
            'packets': 0,
            'received_end': 0,
            'dropped_end': 0
        }
        return stats

    @staticmethod
    def __initial_flags() -> Dict[str, bool]:
        """
        Return initial flags describing state of the running process.
        :rtype: Dict[str, bool]
        """
        flags = dict()
        flags['network_disconnected'] = False
        """Set if the network adapter on which the capture was being done is no longer running;."""
        return flags

    def update(self):
        """
        Update state of running process from process' feedback.
        Read new output from stdout and stderr, check if process is alive.
        :rtype: Dumpcap
        """
        super().update()
        # Is process running? State would be changed after reading stdout and stderr.
        self.poll()

        # check every added line in stderr
        if self.stderr_r and not self.stderr_r.closed:
            for line in self.stderr_r:
                if line == '\n':
                    continue
                if self.CRE_NETWORK_DISCONNECTED.match(line):
                    self.flags['network_disconnected'] = True
                if self.state == self.State.STARTED:
                    if "Capturing on '" + self.interface.name + "'\n" == line:
                        continue
                    m = self.CRE_CAP_FILE_PATH.match(line)
                    if m:
                        detected_cap_file_path = m.group('cap_file_path')
                        if self.capture_file:
                            assert detected_cap_file_path == '-'
                            detected_cap_file_path = self.capture_file  # for the following log
                        else:
                            self.tmp_capture_file_path = detected_cap_file_path
                        logger.debug("Saving capture to '{}'.".format(detected_cap_file_path))
                        self.state = self.State.AWAITING_PACKETS
                        continue
                    assert False, 'Unexpected stderr of dumpcap.' + line + str(self)

                elif self.state == self.State.AWAITING_PACKETS:
                    m = self.CRE_PACKETS.match(line)
                    if m:
                        self.stats['packets'] = int(m.group('packets'))
                        self.state = self.State.CAPTURING
                        continue
                    if self.CRE_SUMMARY1.match(line):
                        self.state = self.State.STOPPING
                        continue
                    assert False, 'Unexpected stderr of dumpcap.' + line + str(self)

                elif self.state == self.State.CAPTURING:
                    m = self.CRE_PACKETS.match(line)
                    if m:
                        self.stats['packets'] = int(m.group('packets'))
                        continue
                    if self.CRE_SUMMARY1.match(line):
                        self.state = self.State.STOPPING
                        continue
                    assert False, 'Unexpected stderr of dumpcap.' + line + str(self)

                elif self.state == self.State.STOPPING:
                    m = self.CRE_SUMMARY2.match(line)
                    if m:
                        self.stats['received_end'] = int(m.group('received'))
                        self.stats['dropped_end'] = int(m.group('dropped'))
                        continue
                    assert False, 'Unexpected stderr of dumpcap.' + line + str(self)

        # check stdout
        if self.stdout_r and not self.stdout_r.closed:
            for line in self.stdout_r:  # type: str
                # NOTE: stdout should be empty
                logger.warning("Unexpected stdout of dumpcap: '{}'. {}".format(line, str(self)))

        # Change state if process was not running in the time of poll() call in the beginning of this method.
        # NOTE: Process' poll() needs to be called in the beginning of this method and returncode checked in the end
        # to ensure all feedback (stdout and stderr) is read and states are changed accordingly.
        # If the process exited, its state is not changed immediately. All available feedback is read and then
        # the state is changed to self.State.TERMINATED. State, flags,stats and others can be changed during reading
        # the available feedback even if the process exited. But self.State.TERMINATED is assigned here if
        # the process exited.
        if self.returncode is not None:
            self.state = self.State.TERMINATED

        return self
