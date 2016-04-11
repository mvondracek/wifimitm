#!/usr/bin/env python3
"""
Functionality for accessing wireless network.

Automatization of MitM Attack on WiFi Networks
Bachelor's Thesis UIFS FIT VUT
Martin Vondracek
2016
"""
import logging
import os
import subprocess

from wep import WepAttacker
from wpa2 import Wpa2Attacker

__author__ = 'Martin Vondracek'
__email__ = 'xvondr20@stud.fit.vutbr.cz'


class ConnectionError(Exception):
    pass


class NotCrackedError(ConnectionError):
    pass


class WirelessUnlocker(object):
    """
    Main class providing attack on wireless network for unlocking it.
    """

    # TODO (xvondr20) Provide some form of feedback during the attack?

    def __init__(self, ap, if_mon):
        """
        :param ap: WirelessAccessPoint object representing the network to be attacked
        :param if_mon: network interface in monitor mode
        """
        self.ap = ap
        self.if_mon = if_mon
        self.if_mon_mac = '00:36:76:54:b2:95'  # TODO (xvondr20) Get real MAC address of if_mon interface.

        self.ap.make_dir()  # make sure that storage for files is prepared

    def start(self, force=False):
        """
        Start attack on wireless network.
        If targeted network have already been cracked and `force` is False, attack is skipped.
        :param force: attack even if network have already been cracked
        """
        if not force and self.ap.is_cracked():
            #  AP already cracked
            logging.info('Known ' + str(self.ap))
            return

        if 'OPN' in self.ap.encryption:
            logging.info('Open ' + str(self.ap))
        elif 'WEP' in self.ap.encryption:
            wep_attacker = WepAttacker(ap=self.ap, if_mon=self.if_mon)
            wep_attacker.start()
            logging.info('Unlocked ' + str(self.ap))
        elif 'WPA' in self.ap.encryption:  # 'WPA', 'WPA2 WPA', 'WPA'
            wpa2_attacker = Wpa2Attacker(ap=self.ap, if_mon=self.if_mon)
            wpa2_attacker.start()
            logging.info('Unlocked ' + str(self.ap))
        else:
            raise NotImplementedError  # NOTE: Any other security than OPN, WEP, WPA, WPA2?


class WirelessConnecter(object):
    """
    Main class providing establishing a connection to the wireless network.
    """

    def __init__(self, interface):
        """
        :param interface: wireless network interface for connection
        """
        self.interface = interface
        self.ap = None
        self.profile = None

    def connect(self, ap):
        """
        Connect to the selected network.
        :param ap: WirelessAccessPoint object representing the network for connection
        Raises:
            NotCrackedError if provided AP requires PSK, but the WirelessAccessPoint object is not cracked
        """
        if 'OPN' not in ap.encryption and not ap.is_cracked():
            raise NotCrackedError()

        self.ap = ap
        self.__create_profile()
        self.__start_profile()
        logging.info('Connected to ' + self.ap.essid)

    def disconnect(self):
        """
        Disconnect from the network.
        """
        self.__stop_profile()
        self.__delete_profile()
        logging.info('Disconnected from ' + self.ap.essid)
        self.ap = None

    def __create_profile(self):
        """
        Create profile for netctl.
        """
        content = "Description='Automatically generated profile by Machine-in-the-middle'\n"
        content += 'Interface=' + self.interface + '\n'
        content += 'Connection=wireless\n'
        content += "ESSID='" + self.ap.essid + "'\n"  # TODO(xvondr20) Quoting rules
        content += 'AP=' + self.ap.bssid + '\n'
        content += 'IP=dhcp\n'

        if 'OPN' in self.ap.encryption:
            content += 'Security=none\n'
        elif 'WEP' in self.ap.encryption:
            content += 'Security=wep\n'
            content += 'Key=\\"' + self.ap.cracked_psk + '\n'  # TODO(xvondr20) Quoting rules
        elif 'WPA' in self.ap.encryption:  # 'WPA', 'WPA2 WPA', 'WPA'
            content += 'Security=wpa\n'
            content += 'Key=' + self.ap.cracked_psk + '\n'  # TODO(xvondr20) Quoting rules

        profile = 'mitm-' + self.interface + '-' + self.ap.essid
        profile_path = os.path.join('/etc/netctl', profile)
        if os.path.isfile(profile_path):
            logging.warning('Existing netctl profile ' + profile + 'overwritten.')

        with open(profile_path, 'w') as f:
            f.write(content)

        self.profile = profile

    def __delete_profile(self):
        """
        Delete profile for netctl.
        """
        if self.profile:
            profile_path = os.path.join('/etc/netctl', self.profile)
            os.remove(profile_path)
            self.profile = None

    def __start_profile(self):
        """
        Start netctl profile.
        Raises:
            CalledProcessError if netctl returncode is non-zero
        """
        cmd = ['netctl', 'start', self.profile]
        process = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        process.check_returncode()

    def __stop_profile(self):
        """
        Stop netctl profile.
        Raises:
            CalledProcessError if netctl returncode is non-zero
        """
        cmd = ['netctl', 'stop', self.profile]
        process = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        process.check_returncode()
