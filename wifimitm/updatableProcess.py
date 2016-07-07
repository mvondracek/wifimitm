#!/usr/bin/env python3
"""
UpdatableProcess Abstract Base Class

Automation of MitM Attack on WiFi Networks
Bachelor's Thesis UIFS FIT VUT
Martin Vondracek
2016
"""

import logging
import os
import subprocess
import tempfile
import warnings
import weakref
from abc import ABC, abstractmethod
from typing import Optional, Sequence, IO, Union

__author__ = 'Martin Vondracek'
__email__ = 'xvondr20@stud.fit.vutbr.cz'

logger = logging.getLogger(__name__)


class UpdatableProcess(ABC, subprocess.Popen):
    """
    Process capable of updating its state based on process' feedback.
    Feedback is considered stdout, stderr, exitcode in case of process' exit and other files created by running process.

    Temporary directory is created for process' feedback.

    Process' stdout and stderr are continuously written to files in the temporary directory. Stdout and stderr can be
    independently read using `self.stdout_r` and `self.stderr_r` file-like objects.

    Can be used as context manager, on exit from the context, the process is waited and then cleanup is performed.

    Process is started on initialization of the object. Running process should be stopped by `self.stop()` or
    `self.cleanup()` call. Call to `__del__` will stop the process, but `__del__` call is not guaranteed during
    destruction, see `Data model <https://docs.python.org/3.5/reference/datamodel.html>`_.

    On cleanup, finalizer call or `__del__` call, stdout and stderr file-like objects for reading and writing are
    closed, temporary directory and all its content is deleted.
    """
    # default values for destructor in case of unsuccessful initialization
    # Initialization could raise an exception in different places and some of the following attributes could be
    # initialized or not. Destructor needs to know which of them were initialized and therefore which need closing
    # or cleanup.
    tmp_dir = None
    stdout_w = None
    stdout_r = None
    stderr_w = None
    stderr_r = None
    _popen_initialized = False  # important for destructor, see `self.__del__()`
    _finalizer_initialized = False  # important for cleanup called from destructor, see `self.__del__()`

    def __init__(self, args: Sequence[str],
                 stdin: Optional[IO]=None,
                 stdout: Union[IO, bool]=True, stderr: Union[IO, bool]=True):
        """
        Execute a child program in a new process.
        :type args: Sequence[str]
        :param args: sequence of program arguments

        :type stdin: Optional[IO]
        :param stdin: Write file to process' stdin.

        :type stdout: Union[IO, bool]
        :param stdout: Write stdout to provided file instead of writing it to file in /tmp. If False is provided, stdout
        is written to /dev/null. If True is provided, temporary file in temporary directory is created.

        :type stderr: Union[IO, bool]
        :param stderr: Write stderr to provided file instead of writing it to file in /tmp. If False is provided, stderr
        is written to /dev/null. If True is provided, temporary file in temporary directory is created.
        """
        self.cleaned = False
        # temp files (write, read) for stdout and stderr
        self.tmp_dir = tempfile.TemporaryDirectory(prefix=type(self).__name__)

        if stdout is True:
            # capture output to a temporary file
            self.stdout_w = open(os.path.join(self.tmp_dir.name, 'stdout.txt'), mode='wt', buffering=1)
            self.stdout_r = open(os.path.join(self.tmp_dir.name, 'stdout.txt'), mode='rt', buffering=1)
        elif stdout is False:
            # do NOT capture output
            self.stdout_w = subprocess.DEVNULL
        else:
            # write output to provided file
            self.stdout_w = stdout

        if stderr is True:
            # capture output to a temporary file
            self.stderr_w = open(os.path.join(self.tmp_dir.name, 'stderr.txt'), mode='wt', buffering=1)
            self.stderr_r = open(os.path.join(self.tmp_dir.name, 'stderr.txt'), mode='rt', buffering=1)
        elif stdout is False:
            # do NOT capture output
            self.stderr_w = subprocess.DEVNULL
        else:
            # write output to provided file
            self.stderr_w = stdout

        super().__init__(args=args, cwd=self.tmp_dir.name,
                         stdin=stdin, stdout=self.stdout_w, stderr=self.stderr_w, universal_newlines=True, bufsize=1)
        self._popen_initialized = True

        # If subprocess.DEVNULL was passed to Popen above, finalizer doesn't need to close it.
        if self.stdout_w == subprocess.DEVNULL:
            self.stdout_w = None
        if self.stderr_w == subprocess.DEVNULL:
            self.stderr_w = None

        self._finalizer = weakref.finalize(
            self, self._cleanup,
            files=[self.stdout_w, self.stdout_r, self.stderr_w, self.stderr_r], tmp_dir=self.tmp_dir)
        self._finalizer_initialized = True

        logger.debug('{!s} started; stdout @ {!s}, stderr @ {!s}'.format(
            type(self).__name__,
            self.stdout_w.name if self.stdout_w else None,
            self.stderr_w.name if self.stderr_w else None)
        )

    @abstractmethod
    def update(self):
        """
        Update state of running process from process' feedback.
        Warning:
            When reading stdout and stderr, use `self.stdout_r` and `self.stderr_r`. Remember to *always* check if these
            files are open, i.e., `not self.stdout_r.closed` and `not self.stderr_r.closed`.
        """
        if self.cleaned:
            raise ValueError("Can't call update on process after cleanup was performed.")

    def stop(self):
        """
        Stop process if it's running.
        """
        if self.cleaned:
            raise ValueError("Can't call stop on process after cleanup was performed.")
        if self.poll() is None:
            # process is running
            self.terminate()
            try:
                logger.debug('Waiting for {} process to terminate.'.format(type(self).__name__))
                self.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.kill()
                logger.warning('Process {} killed after unsuccessful termination.'.format(type(self).__name__))
            else:
                logger.debug('Process {} terminated.'.format(type(self).__name__))

        self.update()

    def cleanup(self, stop=True):
        """
        Cleanup after running process.
        Temp files are closed and deleted,
        :param stop: Stop process if it's running.
        """
        # if the process is running, stop it and then clean
        if stop and self.poll() is None:
            self.stop()
        # close and delete opened temp files
        # If cleanup is called from __del__ after unsuccessful initialization, `self._finalizer` could be uninitialized.
        if self._finalizer_initialized:
            self._finalizer.detach()
        self._cleanup(files=[self.stdout_w, self.stdout_r, self.stderr_w, self.stderr_r], tmp_dir=self.tmp_dir)
        self.cleaned = True

    @staticmethod
    def _cleanup(files, tmp_dir: Optional[tempfile.TemporaryDirectory] = None):
        """
        Close files and cleanup temporary directory.
        :param files: sequence of files to be closed, can contain None
        :type tmp_dir: Optional[tempfile.TemporaryDirectory]
        :param tmp_dir: temporary directory to be cleaned, can be None
        """
        for file in files:
            if file:
                file.close()
        if tmp_dir:
            tmp_dir.cleanup()

    def __enter__(self):
        """
        :rtype: UpdatableProcess
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Stop the process and then do cleanup.
        :param exc_type: Exception type
        :param exc_val: Exception value
        :param exc_tb: Exception traceback information
        """
        self.stop()
        # "...on exit, standard file descriptors are closed, and the process is waited for."
        # `subprocess — Subprocess management <https://docs.python.org/3/library/subprocess.html#subprocess.Popen>`_
        super().__exit__(exc_type, exc_val, exc_tb)
        self.update()
        # close files used for feedback
        self.cleanup()

    def __del__(self, **kwargs):
        """
        Destruct object and perform cleanup.
        If the process is still running, it is stopped and warning is generated. Process should be stopped by calling
        `self.stop()` or `self.cleanup()` or by exiting the context manager.

        Warning:
            "It is not guaranteed that __del__() methods are called for objects that still exist when
            the interpreter exits."`Data model <https://docs.python.org/3.5/reference/datamodel.html>`_

        Warning:
            Destructor of object is called even in case of unsuccessful initialization. If __init__ raised
            an exception, some attributes may be uninitialized. Therefore we need to check `self._popen_initialized`
            before calling methods inherited from popen which access attributes inherited from popen.
        """
        stop_needed = False  # process needs to be stopped
        if self._popen_initialized and self.poll() is None:
            # process is running
            stop_needed = True
            warnings.warn(
                'Process {} was not stopped correctly. Stopping it by destructor, which is not always safe!'.format(
                    type(self).__name__), ResourceWarning)
        super().__del__()
        self.cleanup(stop=stop_needed)
