#!/usr/bin/env python3
"""
Model

Automation of MitM Attack on WiFi Networks
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
import tempfile
from contextlib import contextmanager

__author__ = 'Martin Vondracek'
__email__ = 'xvondr20@stud.fit.vutbr.cz'

logger = logging.getLogger(__name__)


class WirelessStation(object):
    def __str__(self, *args, **kwargs):
        return '<WirelessStation mac_address={}, power={}>'.format(self.mac_address, self.power)

    def __init__(self, mac_address, power):
        self.mac_address = mac_address
        self.power = power

        self.associated_ap = None


class WirelessAccessPoint(object):
    def __str__(self, *args, **kwargs):
        s = '<WirelessAccessPoint essid={}, bssid={}'.format(self.essid, self.bssid)

        if self.is_cracked():
            if 'WEP' in self.encryption:
                s += ', PSK(0x' + self.cracked_psk + ', "' + bytes.fromhex(self.cracked_psk).decode('ascii') + '"), '
            else:
                s += ', PSK("' + self.cracked_psk + '")'

        s += ', power={}, channel={}, encryption={}, cipher={}, authentication={}, wps={}, iv_sum={}>'.format(
            self.power, self.channel, self.encryption, self.cipher, self.authentication, self.wps, self.iv_sum
        )
        return s

    def __init__(self, bssid, power, channel, encryption, cipher, authentication, wps, essid: str, iv_sum):
        self.bssid = bssid  # type: str
        self.power = power  # type: str
        self.channel = channel  # type: str
        self.encryption = encryption  # type: str
        self.cipher = cipher  # type: str
        self.authentication = authentication  # type: str
        self.wps = wps  # type: str
        self.essid = essid  # type: str
        self.iv_sum = iv_sum

        self.__dir_path = None
        self.__temp_dir = None

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
        if not self.__dir_path:
            path = os.path.expanduser(os.path.join('~', '.wifimitm', 'networks', self.essid))
            if path.startswith('~'):
                # expansion failed
                self.__temp_dir = tempfile.TemporaryDirectory(prefix='wifimitm-networks')
                path = self.__temp_dir.name
                logger.warning('Call os.path.expanduser failed.')
            self.__dir_path = path
        return self.__dir_path

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
        return self.psk_path is not None

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

    def delete_psk_file(self):
        """
        Delete PSK file containing hexadecimal cracked key for network.
        """
        if os.path.isfile(self.psk_path):
            os.remove(self.psk_path)
            self.psk_path = None

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
            logger.debug(self.essid + ' arp_cap known')

        if not self.psk_path and os.path.isfile(self.default_psk_path):
            self.psk_path = self.default_psk_path
            logger.debug(self.essid + ' psk known')

        if not self.prga_xor_path and os.path.isfile(self.default_prga_xor_path):
            self.prga_xor_path = self.default_prga_xor_path
            logger.debug(self.essid + ' prga_xor known')

        if not self.wpa_handshake_cap_path and os.path.isfile(self.default_wpa_handshake_cap_path):
            self.wpa_handshake_cap_path = self.default_wpa_handshake_cap_path
            logger.debug(self.essid + ' wpa_handshake_cap known')


def interface_exists(name: str) -> bool:
    """
    Check if interface with given name exists.
    Does not check whether given name is *wireless* interface.
    :type name: str
    :param name: interface name
    :rtype: bool
    :return: True if interface exists, False otherwise.
    """
    return name in netifaces.interfaces()


class WirelessInterface(object):
    def __str__(self, *args, **kwargs):
        s = '<WirelessInterface name={}, mac_address={}, channel={}, driver={}, chipset={}'\
            .format(
                self.name,
                self.mac_address,
                self.channel,
                self.driver,
                self.chipset
            )
        if self.monitor_mode_active:
            s += ', monitor'
        s += '>'
        return s

    def __init__(self, name, driver=None, chipset=None):
        """
        Raises:
            ValueError if name is not a valid interface name
        """
        if not interface_exists(name):
            raise ValueError('You must specify a valid interface name.')

        self.name_original = name
        self.name_monitor = None

        # get MAC address
        self.mac_address_original = self.get_mac_by_name(self.name)
        self.mac_address_spoofed = None

        self.channel = None
        self.monitor_mode_active = False

        # additional data
        self.driver = driver
        self.chipset = chipset

    @staticmethod
    def get_wireless_interface_obj(interface):
        """
        Get WirelessInterface object based on provided argument.
        If interface is already WirelessInterface object, it is just returned. If interface is a valid interface name,
        appropriate WirelessInterface object is created and returned.
        :param interface: WirelessInterface object or string representing valid wireless interface name
        :return: WirelessInterface object
        Raises:
            ValueError if provided interface string is not a valid interface name
            TypeError if provided interface is not a string nor a WirelessInterface object
        """
        if isinstance(interface, WirelessInterface):
            return interface
        elif isinstance(interface, str):
            return WirelessInterface(name=interface)
        else:
            raise TypeError

    @staticmethod
    def get_mac_by_name(name: str) -> str:
        """
        Get MAC address of interface specified by name of the interface.
        :type name: str
        :param name: name of the network interface

        :rtype: str
        :return: string MAC address
        """
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

    @property
    def gateway(self):
        """
        Get current default gateway.
        """
        gateway = None
        gws = netifaces.gateways()
        for gw in gws[netifaces.AF_INET]:
            if gw[1] == self.name:
                gateway = gw[0]
                break
        assert gateway, 'No default gateway available.'
        return gateway

    @contextmanager
    def monitor_mode(self, channel=None):
        self.start_monitor_mode(channel=channel)
        yield
        if self.monitor_mode_active:
            self.stop_monitor_mode()

    def start_monitor_mode(self, channel=None):
        """
        :param channel: monitor interface channel
        Raises:
            CalledProcessError if airmon-ng returncode is non-zero
        """
        assert not self.monitor_mode_active, 'Interface already in monitor mode.'

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
        if process.stderr != '':
            # NOTE: stderr should be empty
            # based on airmon-ng file from aircrack-ng-1.2-rc4
            # (partly checked)
            logger.warning("Unexpected stderr of airmon-ng: '{}'.".format(process.stderr))

        for line in process.stdout.splitlines():
            m = cre_mon_enabled.match(line)
            if m:
                self.monitor_mode_active = True
                self.name_monitor = m.group('mon')
                break

    def stop_monitor_mode(self):
        """
        Raises:
            CalledProcessError if airmon-ng returncode is non-zero
        """
        assert self.monitor_mode_active, 'Interface not in monitor mode.'

        cre_mon_disabled = re.compile(r'^\s+\(\S+ monitor mode vif disabled for \[\S+\](?P<mon>\S+)\)$')

        cmd = ['airmon-ng', 'stop', self.name]
        process = subprocess.run(cmd,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 universal_newlines=True)

        process.check_returncode()
        # check stderr
        if process.stderr != '':
            # NOTE: stderr of should be empty
            # based on airmon-ng file from aircrack-ng-1.2-rc4
            # (partly checked)
            logger.warning("Unexpected stderr of airmon-ng: '{}'.".format(process.stderr))

        for line in process.stdout.splitlines():
            m = cre_mon_disabled.match(line)
            if m:
                self.monitor_mode_active = False
                self.name_monitor = None
                break

    def set_up(self):
        """
        Raises:
            CalledProcessError if process' returncode is non-zero.
        """
        cmd = ['ip', 'link', 'set', self.name, 'up']
        process = subprocess.run(cmd,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 universal_newlines=True)
        process.check_returncode()

    def set_down(self):
        """
        Raises:
            CalledProcessError if process' returncode is non-zero.
        """
        cmd = ['ip', 'link', 'set', self.name, 'down']
        process = subprocess.run(cmd,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 universal_newlines=True)
        process.check_returncode()
