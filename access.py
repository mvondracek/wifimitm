#!/usr/bin/env python3
"""
Functionality for accessing wireless network.

Automatization of MitM Attack on WiFi Networks
Bachelor's Thesis UIFS FIT VUT
Martin Vondracek
2016
"""
import logging

from wep import WepAttacker

__author__ = 'Martin Vondracek'
__email__ = 'xvondr20@stud.fit.vutbr.cz'


class WirelessAttacker(object):
    """
    Main class providing attack on wireless network.
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
        if 'WEP' in self.ap.encryption:
            wep_attacker = WepAttacker(ap=self.ap, if_mon=self.if_mon)
            wep_attacker.start(force=force)
        else:
            raise NotImplementedError  # TODO WPA, WPA2
