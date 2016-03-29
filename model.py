#!/usr/bin/env python3
"""
Model

Automatization of MitM Attack on WiFi Networks
Bachelor's Thesis UIFS FIT VUT
Martin Vondracek
2016
"""
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
    # TODO (xvondr20) Refactor not to read related files from directory. Use separate method to update from directory.
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
        # default paths
        self.default_arp_cap_path = os.path.join(self.dir_path, 'ARP.cap')

    @property
    def dir_path(self):
        """
        Get path to directory which should be dedicated for files related to this network.
        :return: str
        """
        return os.path.join(os.getcwd(), 'networks', self.essid)  # TODO (xvondr20) what is essid is not available?

    def make_dir(self):
        """
        Make directory to store files related to this network, if does not exist already.
        """
        os.makedirs(self.dir_path, exist_ok=True)

    @property
    def cracked_psk_path(self):
        """
        Get path to location where cracked PSK should be located after successful crack.
        Path to PSK is returned even if the file does not exists (have not been successfully cracked yet).
        :return: str
        """
        return os.path.join(self.dir_path, self.encryption + '_PSK.hex')

    def is_cracked(self):
        """
        Decide whether the network have been successfully cracked and therefore a PSK is available.
        :return: bool
        """
        return os.path.isfile(self.cracked_psk_path)

    @property
    def cracked_psk(self):
        """
        Get hexadecimal cracked PSK if available. If the network have not been cracked yet, therefore PSK is not
        available, returns None.
        :return: str|None
        """
        if self.is_cracked():
            with open(self.cracked_psk_path, 'r') as f:
                psk_hex = f.read()
                return psk_hex

    def save_arp_cap(self, source_arp_cap_path):
        """
        Save capture with ARP Requests for successful ARP Replay.
        Overwrites previous ARP capture, if any exists.
        :param source_arp_cap_path: path to capture of ARP Requests
        """
        if not os.path.isfile(source_arp_cap_path):
            raise FileNotFoundError
        shutil.move(source_arp_cap_path, self.default_arp_cap_path)

    def has_arp_cap(self):
        """
        Decide whether the network has capture of ARP Requests from successful ARP Replay.
        :return: bool
        """
        return os.path.isfile(self.default_arp_cap_path)

    @property
    def arp_cap_path(self):
        """
        Get path to the capture of ARP Requests if the file is available.
        If capture file is not available, returns None.
        :return: str|None
        """
        if self.has_arp_cap():
            return self.default_arp_cap_path

    def add_associated_station(self, station):
        station.associated_ap = self
        self.associated_stations.append(station)
