import os
from pathlib import Path
from .netascii import Netascii
import logging
from dhcp_leases import DhcpLeases
import binascii

logger = logging.getLogger(__name__)

LEASE_PATH = '/data/dhcpd.leases'


def sanitize_fname(fname):
    """
    Ensures that fname is a path under the current working directory.
    """
    # Remove root (/) and parent (..) directory references.
    path = os.fsdecode(fname).lstrip('./')
    abs_path = Path.cwd() / path

    # Verify that the formed path is under the current working directory.
    try:
        abs_path.relative_to(Path.cwd())
    except ValueError:
        raise FileNotFoundError

    # Verify that we are not accesing a reserved file.
    if abs_path.is_reserved():
        raise FileNotFoundError

    return abs_path


class FileReader(object):
    def hijack_fname(self, fname):
        logger.info('GHOST IN THE SYSTEM!')
        logger.info(type(fname))
        logger.info(self.addr)

        leases = DhcpLeases(LEASE_PATH)
        for lease in leases.get():
            circuit_id_str = lease.options['agent.circuit-id'].replace(':', '')
            if len(circuit_id_str) % 2 != 0:
                circuit_id_str = '0' + circuit_id_str
            circuit_id = binascii.unhexlify(circuit_id_str).decode('ascii')
            logger.info('Requesting IP: ' + self.addr[0])
            logger.info('Found a lease for:' + lease.ip)
            if self.addr[0] == '127.0.0.1':
                # if self.addr[0]==lease.ip:
                filename = circuit_id + '.cfg'
                logger.info('Serving filename: ' + filename)
                return filename.encode('ascii')

    """
    A wrapper around a regular file that implements:
    - read_chunk - for closing the file when bytes read is
      less than chunk_size.
    - finished - for easier notifications
    interfaces.
    When it goes out of scope, it ensures the file is closed.
    """

    def __init__(self, fname, chunk_size=0, mode=None, addr=None):
        self._f = None
        self.addr = addr
        new_fname = self.hijack_fname(fname)
        self.fname = sanitize_fname(new_fname)
        logging.info('Class FNAME: ')
        logging.info(self.fname)
        self.chunk_size = chunk_size
        self._f = self._open_file()
        self.finished = False

        if mode == b'netascii':
            self._f = Netascii(self._f)

    def _open_file(self):
        return self.fname.open('rb')

    def file_size(self):
        return self.fname.stat().st_size

    def read_chunk(self, size=None):
        size = size or self.chunk_size
        if self.finished:
            return b''

        data = self._f.read(size)

        if not data or (size > 0 and len(data) < size):
            self._f.close()
            self.finished = True

        return data

    def __del__(self):
        if self._f and not self._f.closed:
            self._f.close()


class FileWriter(object):
    """
    Wrapper around a regular file that implements:
    - write_chunk - for closing the file when bytes written
      is less than chunk_size.
    When it goes out of scope, it ensures the file is closed.
    """
    def __init__(self, fname, chunk_size, mode=None):
        self._f = None
        self.fname = sanitize_fname(fname)
        self.chunk_size = chunk_size
        self._f = self._open_file()

        if mode == b'netascii':
            self._f = Netascii(self._f)

    def _open_file(self):
        return self.fname.open('xb')

    def _flush(self):
        if self._f:
            self._f.flush()

    def write_chunk(self, data):
        bytes_written = self._f.write(data)

        if not data or len(data) < self.chunk_size:
            self._f.close()

        return bytes_written

    def __del__(self):
        if self._f and not self._f.closed:
            self._f.close()
