#!/usr/bin/env python3
"""
Functionality for accessing wireless network.

Automation of MitM Attack on WiFi Networks
Bachelor's Thesis UIFS FIT VUT
Martin Vondracek
2016
"""
import logging
import os
import re
import subprocess
from contextlib import contextmanager

from wifimitm.common import WifimitmError
from .model import WirelessInterface, WirelessAccessPoint
from .wep import WepAttacker
from .wpa2 import Wpa2Attacker

__author__ = 'Martin Vondracek'
__email__ = 'xvondr20@stud.fit.vutbr.cz'

logger = logging.getLogger(__name__)


class NotCrackedError(WifimitmError):
    pass


class WirelessUnlocker(object):
    """
    Main class providing attack on wireless network for unlocking it.
    """

    def __init__(self, ap: WirelessAccessPoint, monitoring_interface: WirelessInterface):
        """
        :type ap: WirelessAccessPoint
        :param ap: AP targeted for attack

        :type monitoring_interface: WirelessInterface
        :param monitoring_interface: network interface in monitor mode
        """
        self.ap = ap  # type: WirelessAccessPoint
        self.monitoring_interface = monitoring_interface  # type: WirelessInterface

        self.ap.make_dir()  # make sure that storage for files is prepared

    def start(self, force: bool = False):
        """
        Start attack on wireless network.
        If targeted network have already been cracked and `force` is False, attack is skipped.
        :type force: bool
        :param force: attack even if network have already been cracked
        """
        assert self.monitoring_interface.monitor_mode_active, 'Interface not in monitor mode.'
        assert self.ap.encryption in ['OPN', 'WEP', 'WPA', 'WPA2'], "Invalid encryption type '{}'. "\
            .format(self.ap.encryption)  # based on airodump-ng.c from aircrack-ng-1.2-rc4

        if not force and self.ap.is_cracked():
            #  AP already cracked
            logger.info('Known ' + str(self.ap))
            return

        if 'OPN' in self.ap.encryption:
            logger.info('Open ' + str(self.ap))
        elif 'WEP' in self.ap.encryption:
            wep_attacker = WepAttacker(ap=self.ap, monitoring_interface=self.monitoring_interface)
            wep_attacker.start()
            logger.info('Unlocked ' + str(self.ap))
        elif 'WPA' in self.ap.encryption:  # 'WPA', 'WPA2 WPA', 'WPA'
            wpa2_attacker = Wpa2Attacker(ap=self.ap, monitoring_interface=self.monitoring_interface)
            wpa2_attacker.start()
            logger.info('Unlocked ' + str(self.ap))


class WirelessConnecter(object):
    """
    Main class providing establishing a connection to the wireless network.
    """

    def __init__(self, interface: WirelessInterface):
        """
        :type interface: WirelessInterface
        :param interface: wireless interface for connection
        """
        self.interface = interface  # type: WirelessInterface
        self.ap = None
        self.profile = None

    def connect(self, ap: WirelessAccessPoint):
        """
        Connect to the selected network.
        :param ap: WirelessAccessPoint object representing the network for connection
        Raises:
            NotCrackedError if provided AP requires PSK, but the WirelessAccessPoint object is not cracked
        """
        if 'OPN' not in ap.encryption and not ap.is_cracked():
            raise NotCrackedError()

        self.ap = ap  # type: WirelessAccessPoint
        logger.info('Connecting to ' + self.ap.essid)
        self.__create_profile()
        self.interface.set_down()
        self.__start_profile()
        logger.info('Connected to ' + self.ap.essid)

    def disconnect(self):
        """
        Disconnect from the network.
        """
        self.__stop_profile()
        self.__delete_profile()
        logger.info('Disconnected from ' + self.ap.essid)
        self.ap = None

    @contextmanager
    def connection(self, ap: WirelessAccessPoint):
        self.connect(ap=ap)
        yield
        self.disconnect()

    def __create_profile(self):
        """
        Create profile for netctl.
        """
        # NOTE: Special quoting rules https://github.com/joukewitteveen/netctl/blob/master/docs/netctl.profile.5.txt
        content = "Description='Automatically generated profile by wifimitm - Wi-Fi Machine-in-the-middle'\n"
        content += 'Interface=' + self.interface.name + '\n'
        content += 'Connection=wireless\n'
        content += "ESSID='" + self.ap.essid.replace("'", "'\\''") + "'\n"
        content += 'AP=' + self.ap.bssid + '\n'
        content += 'IP=dhcp\n'

        if 'OPN' in self.ap.encryption:
            content += 'Security=none\n'
        elif 'WEP' in self.ap.encryption:
            content += 'Security=wep\n'
            content += 'Key=\\"' + self.ap.cracked_psk + '\n'
        elif 'WPA' in self.ap.encryption:  # 'WPA', 'WPA2 WPA', 'WPA'
            content += 'Security=wpa\n'
            content += "Key='" + self.ap.cracked_psk.replace("'", "'\\''") + "'\n"

        profile = 'wifimitm-' + self.interface.name + '-' + self.ap.essid
        profile_path = os.path.join('/etc/netctl', profile)
        if os.path.isfile(profile_path):
            logger.warning('Existing netctl profile ' + profile + ' overwritten.')
            self.__stop_profile(profile)

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
        process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.check_returncode()

    def __stop_profile(self, force_profile_name=None):
        """
        Stop netctl profile.
        Raises:
            CalledProcessError if netctl returncode is non-zero
        """
        cmd = ['netctl', 'stop']
        if force_profile_name:
            cmd.append(force_profile_name)
        else:
            cmd.append(self.profile)
        process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.check_returncode()
        logger.debug('OK ' + ' '.join(cmd))


def list_wifi_interfaces():
    """
    List available wireless interfaces presented by airmon-ng.
    Invalid interface names, not recognized by netifaces, are skipped and warning is logged.
    Raises:
        CalledProcessError if airmon-ng returncode is non-zero
    :return: list of WirelessInterface objects
    """
    cre_header = re.compile(r'^PHY\s+Interface\s+Driver\s+Chipset$')
    cre_interface = re.compile(r'^(?P<phy>\S+)\s+(?P<name>\S+)\s+(?P<driver>\S+)\s+(?P<chipset>.+)$')

    process = subprocess.run('airmon-ng',
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             universal_newlines=True,
                             check=True)

    # check stderr
    if process.stderr != '':
        # NOTE: stderr should be empty
        # based on airmon-ng file from aircrack-ng-1.2-rc4 (partly checked)
        logger.warning("Unexpected stderr of airmon-ng: '{}'.".format(process.stderr))

    interfaces = list()
    header_found = False
    for line in process.stdout.splitlines():
        if line == '':
            continue
        if not header_found and cre_header.match(line):
            header_found = True
            continue
        m = cre_interface.match(line)
        if header_found and m:
            # correct output line detected
            try:
                i = WirelessInterface(name=m.group('name'), driver=m.group('driver'), chipset=m.group('chipset'))
            except ValueError:
                logger.warning('Invalid interface name ' + m.group('name') + ' presented by airmon-ng.')
            else:
                interfaces.append(i)
        else:
            assert False, 'Unexpected output of airmon-ng'

    return interfaces
