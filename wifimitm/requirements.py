#!/usr/bin/env python3
"""
Requirements

Automation of MitM Attack on WiFi Networks
Bachelor's Thesis UIFS FIT VUT
Martin Vondracek
2016
"""
import logging
import os
import shutil
from abc import ABC, abstractmethod
from typing import List

from wifimitm.common import WifimitmError

__author__ = 'Martin Vondracek'
__email__ = 'xvondr20@stud.fit.vutbr.cz'

logger = logging.getLogger(__name__)


class Requirement(ABC):
    """
    Requirement Abstract Base Class
    """

    @abstractmethod
    def check(self) -> bool:
        """
        Check if requirement is ok.
        :rtype: bool
        :return: True if requirement is ok, False otherwise.
        """

    @property
    @abstractmethod
    def msg(self) -> str:
        """
        Message that requirement is not ok.
        :rtype: str
        """


class RequirementError(WifimitmError):
    def __init__(self, requirement: Requirement):
        """
        :type requirement: Requirement
        """
        super().__init__()
        self.requirement = requirement


class CommandRequirement(Requirement):
    """
    Requirement for an executable command.
    """

    def __init__(self, cmd: str):
        """
        :type cmd: str
        :param cmd: required executable command
        """
        self.cmd = cmd

    def __str__(self) -> str:
        """
        :rtype: str
        """
        return '<{} cmd={}>'.format(type(self).__name__, self.cmd)

    def check(self) -> bool:
        """
        Check if executable command exists.
        :rtype: bool
        """
        return shutil.which(self.cmd) is not None

    @property
    def msg(self) -> str:
        """
        Message that executable command does not exist.
        :rtype: str
        """
        return "Required command '{}' does not exist.".format(self.cmd)


class UidRequirement(Requirement):
    """
    Requirement for a current process’s real user id.
    """

    UID_ROOT = 0

    def __init__(self, uid: int):
        """
        :type uid: int
        :param uid: required real user id
        """
        self.uid = uid

    def __str__(self) -> str:
        """
        :rtype: str
        """
        return '<{} uid={}>'.format(type(self).__name__, self.uid)

    def check(self) -> bool:
        """
        Check if current process’s real user id is equal to the required one.
        :rtype: bool
        """
        return os.getuid() == self.uid

    @property
    def msg(self) -> str:
        """
        Message that current process’s real user id is not equal to the required one .
        :rtype: str
        """
        msg = 'Required to be run as user with uid={}.'.format(str(self.uid))
        if self.uid == self.UID_ROOT:
            msg += ' (root)'
        return msg


class Requirements(object):
    """
    Requirements class providing Requirement evidence and checking.
    """

    REQUIREMENTS = [
        CommandRequirement('aircrack-ng'),
        CommandRequirement('wpaclean'),
        CommandRequirement('airmon-ng'),
        CommandRequirement('rfkill'),
        CommandRequirement('airodump-ng'),
        CommandRequirement('aireplay-ng'),
        CommandRequirement('netctl'),
        CommandRequirement('wpa_supplicant'),
        CommandRequirement('dumpcap'),
        CommandRequirement('mitmf'),
        CommandRequirement('upc_keys'),
        CommandRequirement('wifiphisher'),
        CommandRequirement('grep'),
        CommandRequirement('sed'),
        CommandRequirement('tcpdump'),  # for MITMf
        CommandRequirement('hostapd'),  # for wifiphisher
        CommandRequirement('dnsmasq'),  # for wifiphisher
        UidRequirement(UidRequirement.UID_ROOT)
    ]  # type: List[Requirement]

    @classmethod
    def check_all(cls) -> bool:
        """
        Check all requirements whether they are ok.
        Raises:
            RequirementError If checked requirement is not ok, Requirement object is available as a `requirement`
                attribute of the raised exception.
        """
        for r in cls.REQUIREMENTS:
            if not r.check():
                logger.critical('requirement check failed {!s}'.format(r))
                raise RequirementError(r)
            else:
                logger.debug('requirement check OK {!s}'.format(r))
