#!/usr/bin/env python3
"""
Model

Automatization of MitM Attack on WiFi Networks
Bachelor's Thesis UIFS FIT VUT
Martin Vondracek
2016
"""
import logging
import netifaces
import os
import re
import shutil
import subprocess

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
            if 'WEP' in self.encryption:
                s += ', PSK(0x' + self.cracked_psk + ', "' + bytes.fromhex(self.cracked_psk).decode('ascii') + '"), '
            else:
                s += ', PSK("' + self.cracked_psk + '"), '

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
        self.wpa_handshake_cap_path = None
        """path to the capture of WPA handshake, if available"""

        # default paths
        self.default_arp_cap_path = os.path.join(self.dir_path, 'ARP.cap')
        if 'WEP' in self.encryption:
            self.default_psk_path = os.path.join(self.dir_path, self.encryption + '_PSK.hex')
        else:
            self.default_psk_path = os.path.join(self.dir_path, self.encryption + '_PSK.txt')
        self.default_prga_xor_path = os.path.join(self.dir_path, 'PRGA.xor')
        self.default_wpa_handshake_cap_path = os.path.join(self.dir_path, 'WPA_handshake.cap')

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
        Get cracked PSK if available.
        If encryption is WEP, PSK is hexadecimal sequence. If encryption is WPA or WPA2, PSK is ASCII sequence.
        If the network have not been cracked yet, therefore PSK is not available, returns None.
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

    def save_wpa_handshake_cap(self, source_wpa_handshake_cap_path):
        """
        Save capture with WPA handshake.
        Overwrites previous file, if any exists.
        :param source_wpa_handshake_cap_path: path to capture with WPA handshake
        """
        if not os.path.isfile(source_wpa_handshake_cap_path):
            raise FileNotFoundError
        shutil.move(source_wpa_handshake_cap_path, self.default_wpa_handshake_cap_path)
        self.wpa_handshake_cap_path = self.default_wpa_handshake_cap_path

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

        if not self.wpa_handshake_cap_path and os.path.isfile(self.default_wpa_handshake_cap_path):
            self.wpa_handshake_cap_path = self.default_wpa_handshake_cap_path
            logging.debug(self.essid + ' wpa_handshake_cap known')


class WirelessInterface(object):
    def __str__(self, *args, **kwargs):  # TODO (xvondr20) just for debugging
        s = 'WirelessInterface(' + ', '.join([
            self.name,
            self.mac_address,
            self.channel,
            self.driver,
            self.chipset
        ])
        if self.monitor_mode:
            s += ', monitor'
        s += ')'
        return s

    def __init__(self, name, driver=None, chipset=None):
        """
        Raises:
            ValueError if name is not a valid interface name
        """
        self.name_original = name
        self.name_monitor = None

        # get MAC address
        self.mac_address_original = self.get_mac_by_name(self.name)
        self.mac_address_spoofed = None

        self.channel = None
        self.monitor_mode = False

        # additional data
        self.driver = driver
        self.chipset = chipset

    @staticmethod
    def get_mac_by_name(name):
        """
        Get MAC address of interface specified by name of the interface.
        :return: string MAC address
        """
        # TODO(xvondr20) Is this safe?
        ifa = netifaces.ifaddresses(name)
        mac = ifa[netifaces.AF_LINK][0]['addr']
        return mac

    @property
    def mac_address(self):
        """
        Get current MAC address.
        """
        assert self.mac_address_spoofed or self.mac_address_original, 'No MAC address available.'

        if self.mac_address_spoofed:
            return self.mac_address_spoofed
        else:
            return self.mac_address_original

    @property
    def name(self):
        """
        Get current interface name.
        """
        assert self.name_monitor or self.name_original, 'No interface name available.'

        if self.name_monitor:
            return self.name_monitor
        else:
            return self.name_original

    def start_monitor_mode(self, channel=None):
        """
        :param channel: monitor interface channel
        Raises:
            CalledProcessError if airmon-ng returncode is non-zero
        """
        assert not self.monitor_mode, 'Interface already in monitor mode.'

        cre_mon_enabled = re.compile(
            r'^\s+\(\S+ monitor mode vif enabled for \[\S+\](?P<name>\S+) on \[\S+\](?P<mon>\S+)\)$')

        cmd = ['airmon-ng', 'start', self.name]
        if channel:
            cmd.append(str(channel))
            self.channel = channel
        process = subprocess.run(cmd,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 universal_newlines=True)

        process.check_returncode()
        # check stderr
        # TODO (xvondr20) Does 'airmon-ng' ever print anything to stderr?
        assert process.stderr == ''

        for line in process.stdout.splitlines():
            m = cre_mon_enabled.match(line)
            if m:
                self.monitor_mode = True
                self.name_monitor = m.group('mon')
                break

    def stop_monitor_mode(self):
        """
        Raises:
            CalledProcessError if airmon-ng returncode is non-zero
        """
        assert self.monitor_mode, 'Interface not in monitor mode.'

        cre_mon_disabled = re.compile(r'^\s+\(\S+ monitor mode vif disabled for \[\S+\](?P<mon>\S+)\)$')

        cmd = ['airmon-ng', 'stop', self.name]
        process = subprocess.run(cmd,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 universal_newlines=True)

        process.check_returncode()
        # check stderr
        # TODO (xvondr20) Does 'airmon-ng' ever print anything to stderr?
        assert process.stderr == ''

        for line in process.stdout.splitlines():
            m = cre_mon_disabled.match(line)
            if m:
                self.monitor_mode = False
                self.name_monitor = None
                break
