#!/usr/bin/env python3
"""
Model

Automatization of MitM Attack on WiFi Networks
Bachelor's Thesis UIFS FIT VUT
Martin Vondracek
2016
"""
import logging
import os
import shutil

__author__ = 'Martin Vondracek'
__email__ = 'xvondr20@stud.fit.vutbr.cz'


class WirelessStation(object):
    def __str__(self, *args, **kwargs):  # TODO (xvondr20) just for debugging
        return 'WirelessStation(' + ', '.join([
            self.mac_address,
            self.power
        ]) + ')'

    def __init__(self, mac_address, power):
        self.mac_address = mac_address
        self.power = power

        self.associated_ap = None


class WirelessAccessPoint(object):
    def __str__(self, *args, **kwargs):  # TODO (xvondr20) just for debugging
        s = 'WirelessAccessPoint(' + ', '.join([
            self.essid,
            self.bssid
        ])

        if self.is_cracked():
            s += ', PSK(0x' + self.cracked_psk + ', "' + bytes.fromhex(self.cracked_psk).decode('ascii') + '"), '

        s += ', '.join([
            self.power,
            self.channel,
            self.encryption,
            self.cipher,
            self.authentication,
            str(self.wps),
            self.iv_sum
        ]) + ')'
        return s

    def __init__(self, bssid, power, channel, encryption, cipher, authentication, wps, essid, iv_sum):
        self.bssid = bssid
        self.power = power
        self.channel = channel
        self.encryption = encryption
        self.cipher = cipher
        self.authentication = authentication
        self.wps = wps
        self.essid = essid
        self.iv_sum = iv_sum

        self.associated_stations = list()

        self.arp_cap_path = None
        """path to the capture of ARP Requests, if available"""
        self.psk_path = None
        """path to the file containing hexadecimal PSK, if available"""
        self.prga_xor_path = None
        """path to the file containing PRGA XOR keystream, if available"""

        # default paths
        self.default_arp_cap_path = os.path.join(self.dir_path, 'ARP.cap')
        self.default_psk_path = os.path.join(self.dir_path, self.encryption + '_PSK.hex')
        self.default_prga_xor_path = os.path.join(self.dir_path, 'PRGA.xor')

    @property
    def dir_path(self):
        """
        Get path to directory which should be dedicated for files related to this network.
        It the directory does not exist, the attacker is responsible for its creation using `self.make_dir()`.
        :return: str
        """
        return os.path.join(os.getcwd(), 'networks', self.essid)  # TODO (xvondr20) what is essid is not available?

    def make_dir(self):
        """
        Make directory to store files related to this network, if does not exist already.
        """
        os.makedirs(self.dir_path, exist_ok=True)

    def is_cracked(self):
        """
        Decide whether the network have been successfully cracked and therefore a PSK is available.
        :return: bool
        """
        return self.psk_path is not None  # TODO(xvondr20) WPS?

    @property
    def cracked_psk(self):
        """
        Get hexadecimal cracked PSK if available. If the network have not been cracked yet, therefore PSK is not
        available, returns None.
        :return: str|None
        """
        if self.psk_path:
            with open(self.psk_path, 'r') as f:
                return f.read()

    def save_arp_cap(self, source_arp_cap_path):
        """
        Save capture with ARP Requests for successful ARP Replay.
        Overwrites previous file, if any exists.
        :param source_arp_cap_path: path to capture of ARP Requests
        """
        if not os.path.isfile(source_arp_cap_path):
            raise FileNotFoundError
        shutil.move(source_arp_cap_path, self.default_arp_cap_path)
        self.arp_cap_path = self.default_arp_cap_path

    def save_psk_file(self, source_psk_file_path):
        """
        Save PSK file containing hexadecimal cracked key for network.
        Overwrites previous file, if any exists.
        :param source_psk_file_path: path to PSK file
        """
        if not os.path.isfile(source_psk_file_path):
            raise FileNotFoundError
        shutil.move(source_psk_file_path, self.default_psk_path)
        self.psk_path = self.default_psk_path

    def save_prga_xor(self, source_prga_xor_path):
        """
        Save file containing PRGA XOR keystream.
        Overwrites previous file, if any exists.
        :param source_prga_xor_path: path to file containing PRGA XOR keystream
        """
        if not os.path.isfile(source_prga_xor_path):
            raise FileNotFoundError
        shutil.move(source_prga_xor_path, self.default_prga_xor_path)
        self.prga_xor_path = self.default_prga_xor_path

    def add_associated_station(self, station):
        station.associated_ap = self
        self.associated_stations.append(station)

    def update_known(self):
        """
        Update known network based on saved files.
        """
        if not self.arp_cap_path and os.path.isfile(self.default_arp_cap_path):
            self.arp_cap_path = self.default_arp_cap_path
            logging.debug(self.essid + ' arp_cap known')

        if not self.psk_path and os.path.isfile(self.default_psk_path):
            self.psk_path = self.default_psk_path
            logging.debug(self.essid + ' psk known')

        if not self.prga_xor_path and os.path.isfile(self.default_prga_xor_path):
            self.prga_xor_path = self.default_prga_xor_path
            logging.debug(self.essid + ' prga_xor known')
