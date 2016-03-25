#!/usr/bin/env python3
"""
sandbox file for testing available functionality

Automatization of MitM Attack on WiFi Networks
Bachelor's Thesis UIFS FIT VUT
Martin Vondracek
2016
"""

import sys

from wep import *

__author__ = 'Martin Vondracek'
__email__ = 'xvondr20@stud.fit.vutbr.cz'


def main():
    logging.basicConfig(format='[%(asctime)s] %(funcName)s: %(message)s', level=logging.DEBUG)

    with tempfile.TemporaryDirectory(prefix='test-wep-osa-') as tmp_dirname:
        if_mon = 'wlp0s20u1u1mon'
        scanner = WirelessScanner(tmp_dir=tmp_dirname, interface=if_mon)
        scan = scanner.scan_once()

        for ap in scan:
            if ap.essid == 'test-wep-osa':
                logging.info('scan found test-wep-osa')

                dir_network_path = os.path.join(os.getcwd(), 'networks', ap.essid)
                os.makedirs(dir_network_path, exist_ok=True)

                wep_attacker = WepAttacker(
                    dir_network_path=dir_network_path,
                    ap=ap,
                    if_mon=if_mon)
                wep_attacker.start()

    return 0


if __name__ == '__main__':
    status = main()
    sys.exit(status)
