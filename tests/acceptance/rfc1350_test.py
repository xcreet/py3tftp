import unittest
import socket
import struct
import hashlib
from io import BytesIO
from os import remove as rm
from os.path import exists
from time import sleep


RRQ = b'\x00\x01'
WRQ = b'\x00\x02'
DAT = b'\x00\x03'
ACK = b'\x00\x04'
ERR = b'\x00\x05'

NOFOUND = b'\x00\x01'
ACCVIOL = b'\x00\x02'
EEXISTS = b'\x00\x06'


class TestRRQ(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open('LICENSE', 'rb') as f:
            cls.license = f.read()
        cls.license_md5 = hashlib.md5(cls.license).hexdigest()
        cls.server_addr = ('127.0.0.1', 8069,)
        cls.rrq = RRQ + b'LICENSE\x00binary\x00'

    def setUp(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.counter = 1
        self.output = []
        self.data = None
        self.s.sendto(self.rrq, self.server_addr)

    def tearDown(self):
        self.s.close()

    def test_perfect_scenario(self):
        while True:
            self.data, server = self.s.recvfrom(1024)
            self.output += self.data[4:]

            msg = ACK + self.counter.to_bytes(2, byteorder='big')
            self.s.sendto(msg, server)
            self.counter += 1

            if len(self.data[4:]) < 512:
                break

        received = bytes(self.output)
        received_md5 = hashlib.md5(received).hexdigest()
        self.assertEqual(len(self.license), len(received))
        self.assertTrue(self.license_md5 == received_md5)

    def test_no_acks(self):
        no_ack = True
        while True:
            self.data, server = self.s.recvfrom(1024)
            if self.counter % 5 == 0 and no_ack:
                # dont ack, discard data
                no_ack = False
            else:
                no_ack = True
                self.output += self.data[4:]

                msg = ACK + self.counter.to_bytes(2, byteorder='big')
                self.s.sendto(msg, server)
                self.counter += 1

                if len(self.data[4:]) < 512:
                    break

        received = bytes(self.output)
        received_md5 = hashlib.md5(received).hexdigest()
        self.assertEqual(len(self.license), len(received))
        self.assertTrue(self.license_md5 == received_md5)

    def test_total_timeout(self):
        max_msgs = 15
        while True:
            self.data, server = self.s.recvfrom(1024)
            if self.counter >= max_msgs:
                break

            self.output += self.data[4:]
            msg = ACK + self.counter.to_bytes(2, byteorder='big')

            self.s.sendto(msg, server)
            self.counter += 1

            if len(self.data[4:]) < 512:
                break
        received = bytes(self.output)
        self.assertEqual((max_msgs - 1) * 512, len(received))


class TestWRQ(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.license_buf = BytesIO()
        with open('LICENSE', 'rb') as f:
            license = f.read()
            cls.license_buf.write(license)
            cls.license_buf.seek(0)
            cls.license_md5 = hashlib.md5(license).hexdigest()
        cls.server_addr = ('127.0.0.1', 8069,)
        cls.wrq = WRQ + b'LICENSE_TEST\x00binary\x00'

    def setUp(self):
        if exists('LICENSE_TEST'):
            rm('LICENSE_TEST')
        self.license = iter(lambda: self.license_buf.read(512), b'')
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.sendto(self.wrq, self.server_addr)

    def tearDown(self):
        self.license_buf.seek(0)
        self.s.close()

    def test_perfect_transfer(self):
        for i, chunk in enumerate(self.license):
            ack, server = self.s.recvfrom(1024)
            self.assertEqual(ack, ACK + i.to_bytes(2, byteorder='big'))
            self.s.sendto(DAT + (i + 1).to_bytes(2,
                                                 byteorder='big') + chunk,
                          server)

        sleep(1)
        with open('LICENSE_TEST', 'rb') as f:
            license_test = f.read()
            license_test_md5 = hashlib.md5(license_test).hexdigest()

        self.assertEqual(len(license_test), self.license_buf.tell())
        self.assertEqual(self.license_md5, license_test_md5)

    def test_lost_data_packet(self):
        last_pkt = None
        counter = 0
        outbound_data = self.license
        while True:
            ack, server = self.s.recvfrom(1024)
            if counter > 0 and counter % 10 == 0 and pkt != last_pkt:
                pkt = last_pkt
            else:
                try:
                    pkt = next(outbound_data)
                except StopIteration:
                    break
                counter += 1

            self.s.sendto(DAT +
                          (counter).to_bytes(2,
                                             byteorder='big') + pkt,
                          server)
            last_pkt = pkt

        sleep(1)
        with open('LICENSE_TEST', 'rb') as f:
            license_test = f.read()
            license_test_md5 = hashlib.md5(license_test).hexdigest()

        self.assertEqual(len(license_test), self.license_buf.tell())
        self.assertEqual(self.license_md5, license_test_md5)

    def test_drop_client_connection(self):
        PKTS_BEFORE_DISCONNECT = 15
        for i, chunk in enumerate(self.license):
            ack, server = self.s.recvfrom(1024)
            print(ack)
            if i >= PKTS_BEFORE_DISCONNECT:
                break
            self.s.sendto(DAT + (i + 1).to_bytes(2,
                                                 byteorder='big') + chunk,
                          server)

        # wait for timeout to close file
        sleep(3.1)
        with open('LICENSE_TEST', 'rb') as f:
            license_test = f.read()

        self.assertEqual(len(license_test), self.license_buf.tell() - 512)

    @unittest.skip('')
    def test_access_violation_error(self):
        pass

    @unittest.skip('')
    def test_disk_full(self):
        pass

    @unittest.skip('')
    def test_file_already_exists(self):
        pass


class TestRRQErrors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server_addr = ('127.0.0.1', 8069,)

    def setUp(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def tearDown(self):
        self.s.close()

    def test_file_not_found(self):
        no_such_file = RRQ + b'NOSUCHFILE\x00binary\x00'
        self.s.sendto(no_such_file, self.server_addr)
        data, server = self.s.recvfrom(512)
        self.assertEqual(ERR + NOFOUND, data[:4])

    # def test_access_violation(self):
        # no_perms = RRQ + b'NOPERMS\x00binary\x00'
        # self.s.sendto(no_perms, self.server_addr)
        # data, server = self.s.recvfrom(512)
        # self.assertEqual(ERR + ACCVIOL, data[:4])

    @unittest.skip('')
    def test_illegal_tftp_operation(self):
        pass

    @unittest.skip('')
    def test_unknown_transfer_id(self):
        # send packet where source is different from remote_addr
        # must reply with err #4
        pass

    @unittest.skip('')
    def test_undefined_error(self):
        pass


if __name__ == '__main__':
    unittest.main()
