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

from access import WirelessAttacker
from common import WirelessScanner

__author__ = 'Martin Vondracek'
__email__ = 'xvondr20@stud.fit.vutbr.cz'


def main():
    logging.basicConfig(format='[%(asctime)s] %(funcName)s: %(message)s', level=logging.DEBUG)

    with tempfile.TemporaryDirectory() as tmp_dirname:
        if_mon = 'wlp0s20u1u1mon'
        scanner = WirelessScanner(tmp_dir=tmp_dirname, interface=if_mon)
        scan = scanner.scan_once()

        target = None
        print('Scan:')
        for ap in scan:
            print(ap)
            if ap.essid == 'test-wep-osa' or ap.essid == 'test-wep-ska':
                target = ap
                logging.info('scan found ' + target.essid)

        if target:
            wireless_attacker = WirelessAttacker(ap=target, if_mon=if_mon)
            wireless_attacker.start()

    return 0


if __name__ == '__main__':
    status = main()
    sys.exit(status)
