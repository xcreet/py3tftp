from typing import Dict, Tuple, Optional, Any, Union, Iterator
import logging
import asyncio

from .exceptions import ProtocolException
import tftp_parsing
from tftp_packet import TFTPPacketFactory


class BaseTFTPProtocol(asyncio.DatagramProtocol, TFTPOptParserMixin):
    supported_opts = {
         b'blksize': tftp_parsing.blksize_parser,
         b'timeout': tftp_parsing.timeout_parser,
    }

    default_opts = {
        b'ack_timeout': 0.5,
        b'timeout': 5.0,
        b'blksize': 512
    }

    def __init__(self, packet: bytes,
                 remote_addr: Tuple[str, int],
                 extra_opts: Optional[Dict[str, Any]] = None) -> None:
        self.remote_addr = remote_addr
        self.packet = packet
        self.extra_opts = extra_opts
        if not self.extra_opts:
            self.extra_opts = {}
        self.retransmit = None
        self.file_iterator = None
        self.finished = False
        self.packet_factory = TFTPPacketFactory(
            supported_opts=self.supported_opts,
            default_opts=self.default_opts)

    def datagram_received(self,
                          data: bytes,
                          addr: Tuple[str, int]) -> None:
        """
        Processes every received datagram.
        """
        raise NotImplementedError

    def initialize_transfer(self) -> None:
        """
        Sets up the message counter and attempts to open the target file for
        reading or writing.
        """
        raise NotImplementedError

    def next_datagram(self) -> bytes:
        """
        Returns the next datagram to be sent to self.remote_addr.
        """
        raise NotImplementedError

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        """
        Triggers connection initialization at the beginning of a connection.
        """
        self.transport = transport
        self.handle_initialization()

    def handle_initialization(self) -> None:
        """
        Sends first packet to self.remote_addr. In the process, it attempts to
        access the requested file - and handles possible file errors - as well
        as handling option negotiation (if applicable).
        """
        try:
            self.set_proto_attributes()
            self.initialize_transfer()

            if self.r_opts:
                self.counter = 0 # type: int
                pkt = self.packet_factory.create_packet('ock', r_opts=self.r_opts)
            else:
                pkt = self.next_datagram()
        except FileExistsError:
            logging.error('"{}" already exists! Cannot overwrite'.format(
                self.filename))
            pkt = self.packet_factory.err_file_exists()
        except PermissionError:
            logging.error('Insufficient permissions to operate on "{}"'.format(
                self.filename))
            pkt = self.packet_factory.err_access_violation()
        except FileNotFoundError:
            logging.error('File "{}" does not exist!'.format(self.filename))
            pkt = self.packet_factory.err_file_not_found()

        logging.debug('opening pkt: {}'.format(pkt))
        self.send_opening_packet(pkt.to_bytes())

        if pkt.is_err():
            self.handle_err_pkt()

    def set_proto_attributes(self) -> None:
        """
        Sets the self.filename , self.opts, and self.r_opts.
        The caller should handle any exceptions and react accordingly
        ie. send error packet, close connection, etc.
        """
        self.filename = self.packet.fname
        self.r_opts = self.packet.r_opts
        logging.debug(self.r_opts)
        self.opts = {**self.default_opts, **self.extra_opts, **self.r_opts}
        logging.debug(self.opts)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """
        Cleans up socket and fd after connection has been lost. Logs an error
        if connection interrupted.
        """
        self.conn_reset()
        if self.file_iterator:
            self.file_iterator.close()
        if exc:
            logging.error(
                'Error on connection lost: {0}.\nTraceback: {1}'.format(
                    exc, exc.__traceback__))
        else:
            logging.info('Connection to {0}:{1} terminated'.format(
                *self.remote_addr))

    def error_received(self, exc: Optional[Exception]) -> None:
        """
        Handles cleanup after socket reports an error ie. local or remote
        socket closed and other network errors.
        """

        self.conn_reset()
        self.transport.close()
        logging.error((
            'Error receiving packet from {0}: {1}. '
            'Transfer of "{2}" aborted.\nTraceback: {3}').format(
                self.remote_addr, exc, self.filename, exc.__traceback__))

    def send_opening_packet(self, packet: bytes) -> None:
        """
        Starts the connection timeout timer and sends first datagram.
        """
        self.reply_to_client(packet)
        self.h_timeout = asyncio.get_event_loop().call_later(
            self.opts['timeout'], self.conn_timeout)

    def reply_to_client(self, packet: bytes) -> None:
        """
        Starts the message retry loop, resending packet to self.remote_addr
        every 'ack_timeout'.
        """
        self.transport.sendto(packet, self.remote_addr)
        self.retransmit = asyncio.get_event_loop().call_later(
            self.opts['ack_timeout'], self.reply_to_client, packet)

    def handle_err_pkt(self) -> None:
        """
        Cleans up connection after sending a courtesy error packet
        to offending client.
        """
        logging.info((
            'Closing connection to {0} due to error. '
            '"{1}" Not transmitted.').format(
                self.remote_addr, self.filename))
        self.conn_reset()
        asyncio.get_event_loop().call_soon(self.transport.close)

    def retransmit_reset(self) -> None:
        """
        Stops the message retry loop.
        """
        if self.retransmit:
            self.retransmit.cancel()

    def conn_reset(self) -> None:
        """
        Stops the message retry loop and the connection timeout timers.
        """
        self.retransmit_reset()
        if self.h_timeout:
            self.h_timeout.cancel()

    def conn_timeout(self) -> None:
        """
        Cleans up timers and the connection when called.
        """

        logging.error(
            'Connection to {0} timed out, "{1}" not transfered'.format(
                self.remote_addr, self.filename))
        self.retransmit_reset()
        self.transport.close()

    def conn_timeout_reset(self) -> None:
        """
        Restarts the connection timeout timer.
        """

        self.conn_reset()
        self.h_timeout = asyncio.get_event_loop().call_later(
            self.opts['timeout'], self.conn_timeout)


    def is_correct_tid(self, addr: Tuple[str, int]) -> bool:
        """
        Checks whether address '(ip, port)' matches that of the
        established remote host.
        May send error to host that submitted incorrect address.
        """
        if self.remote_addr[1] == addr[1]:
            return True
        else:
            logging.warning(
                'Unknown transfer id: expected {0}, got {1} instead.'.format(
                    self.remote_addr, addr))
            self.transport.sendto(self.packet_factory.err_unknown_tid(), addr)
            return False



class WRQProtocol(BaseTFTPProtocol):
    def __init__(self, wrq: bytes, addr: Tuple[str, int],
                 opts: Dict[str, Any]) -> None:
        super().__init__(wrq, addr, opts)
        logging.info('Initiating WRQProtocol with {0}'.format(
            self.remote_addr))


    def next_datagram(self) -> bytes:
        """
        Builds an acknowledgement of a received data packet.
        """
        return self.packet_factory.create_packet(
            type='ack',
            block_no=self.counter)


    def initialize_transfer(self) -> None:
        self.counter = 0
        self.file_iterator = self.get_file_writer(self.filename)

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        """
        Check correctness of received datagram, reset timers, increment
        counter, ACKnowledge datagram, save received data to file.
        """
        packet = self.packet_factory.from_bytes(data)

        if (self.is_correct_tid(addr) and
                packet.is_data() and
                packet.is_correct_sequence(self.counter + 1)):
            self.conn_timeout_reset()

            self.counter += 1
            reply_packet = self.next_datagram()
            self.reply_to_client(reply_packet.to_bytes())

            try:
                self.file_iterator.send(packet.data)
            except StopIteration:
                logging.info('Receiving file "{0}" from {1} completed'.format(
                    self.filename, self.remote_addr))
                self.retransmit_reset()
                self.transport.close()
        else:
            logging.debug('Data: {0}; is_data: {1}; counter: {2}'.format(
                data, self.is_data(data), self.counter))

    def get_file_writer(self, fname: bytes) -> Iterator:
        """
        Returns an iterator function to read a file in blksize blocks.
        """
        fpath = tftp_parsing.sanitize_fname(fname)

        def iterator():
            with open(fpath, 'xb') as f:
                while True:
                    data = yield
                    f.write(data)
                    if len(data) < self.opts[b'blksize']:
                        raise StopIteration
        writer = iterator()
        writer.send(None)
        return writer


class RRQProtocol(BaseTFTPProtocol):
    def __init__(self,
                 rrq: bytes,
                 addr: Tuple[str, int],
                 opts: Dict[str, Any]) -> None:
        super().__init__(rrq, addr, opts)
        logging.info('Initiating RRQProtocol with {0}'.format(
            self.remote_addr))

    def next_datagram(self) -> bytes:
        return self.packet_factory.create_packet(
            type='dat',
            block_no=self.counter,
            data=next(self.file_iterator))

    def initialize_transfer(self) -> None:
        self.counter = 1
        self.file_iterator = self.get_file_reader(self.filename)

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        """
        Checks correctness of incoming datagrams, reset timers,
        increments message counter, send next chunk of requested file
        to client.
        """
        packet = self.packet_factory.from_bytes(bytes)
        if (self.is_correct_tid(addr) and
                packet.is_ack(data) and
                packet.is_correct_sequence(data)):
            self.conn_timeout_reset()
            try:
                self.counter += 1
                packet = self.next_datagram()
                self.reply_to_client(packet.to_bytes())
                if packet.size < self.opts[b'blksize']:
                    self.finished = True
            except StopIteration:
                logging.info('Sending file "{0}" to {1} completed'.format(
                    self.filename, self.remote_addr))
                # case where iterator reads and returns b''
                if not self.finished:
                    # move this out - wrong level of abstraction
                    last_dat = self.packet_factory.create_packet(
                        block_no=self.counter,
                        data=b'')
                    self.reply_to_client(last_dat.to_bytes())
                self.transport.close()
        else:
            logging.debug('Ack: {0}; is_ack: {1}; counter: {2}'.format(
                data, self.is_ack(data), self.counter))

    def get_file_reader(self, fname: bytes) -> Iterator:
        """
        Returns an iterator of a file, read in blksize chunks.
        """
        fpath = tftp_parsing.sanitize_fname(fname)

        def iterator():
            with open(fpath, 'rb') as f:
                for chunk in iter(lambda: f.read(self.opts[b'blksize']), b''):
                    yield chunk
        return iterator()


class BaseTFTPServerProtocol(asyncio.DatagramProtocol):
    def __init__(self,
                 host_interface: str,
                 loop: asyncio.BaseEventLoop,
                 extra_opts: Dict[str, Any]) -> None:
        self.host_interface = host_interface
        self.loop = loop
        self.extra_opts = extra_opts

    def select_protocol(self,
                        request: bytes,
                        remote_addr: Tuple[str, int]) -> BaseTFTPProtocol:
        """
        Selects an asyncio.Protocol-compatible protocol to
        feed to an event loop's 'create_datagram_endpoint'
        function.
        """
        raise NotImplementedError

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        logging.info('Listening...')
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        """
        Opens a read or write connection to remote host by scheduling
        an asyncio.Protocol.
        """
        logging.debug('received: {}'.format(data.decode()))

        protocol = self.select_protocol(data, addr)

        packet = self.packet_factory.from_bytes(data)
        logging.debug('data: {}'.format(data))

        connect = self.loop.create_datagram_endpoint(
            lambda: protocol(packet, addr, self.extra_opts),
            local_addr=(self.host_interface, 0,))

        self.loop.create_task(connect)

    def connection_lost(self, exc: Exception):
        logging.info('TFTP server - connection lost')


class TFTPServerProtocol(BaseTFTPServerProtocol):
    def select_protocol(self,
                        req: bytes,
                        remote_addr: Tuple[str, int]) -> BaseTFTPProtocol:
        tx_type = req[:2]
        logging.debug('tx_type: {}'.format(tx_type))
        if tx_type == RRQ:
            return RRQProtocol
        elif tx_type == WRQ:
            return WRQProtocol
        else:
            raise ProtocolException('Received incompatible request, ignoring.')
