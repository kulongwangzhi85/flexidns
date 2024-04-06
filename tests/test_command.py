
# coding: utf-8

import unittest
from collections import deque
from unittest.mock import patch, MagicMock, Mock
import pickle as cpickle

from dnslib import *

from FlexiDNS.command import CacheOperate, pickle, socket


class Test_Command(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.command = CacheOperate()

    def setUp(self) -> None:
        self.command = Test_Command.command
        self.qname = 'www.flexidns.com'
        self.dnslabel = DNSLabel(self.qname)
        self.rr = RR(self.qname, ttl=60, rdata=A('192.168.1.1'))

    @patch('FlexiDNS.command.CacheOperate.data_recv')
    def test_01_cacheshow_dict(self, data_recv_mock):
        import pickle as cpickle
        cmd = {'cache': {'cmd': 'show', 'all': True, 'qname': None}}
        message = cpickle.dumps(cmd)
        recv_data = {'type': 'cache', 'argparse': 'show', 'data_length': 30, 'data': b''}
        mmdata = {self.dnslabel: {'rr': [self.rr]}}
        result = '      www.flexidns.com.            60     IN     A      192.168.1.1'

        data_recv_mock.return_value=recv_data
        CacheOperate.unloads = MagicMock(return_value=[mmdata])
        pickle.dumps = MagicMock(return_value=message)

        with patch('builtins.print') as print_mock:
            self.command.cache(cmd)
            print_mock.assert_called_once_with(result)

    @patch('FlexiDNS.command.CacheOperate.data_recv')
    def test_02_cacheshow_list(self, data_recv_mock):
        cmd = {'cache': {'cmd': 'show', 'all': False, 'qname': [self.qname]}}
        message = cpickle.dumps(cmd)
        recv_data = {'type': 'cache', 'argparse': 'show', 'data_length': 30, 'data': b''}
        mmdata = [[self.rr]]
        result = '      www.flexidns.com.            60     IN     A      192.168.1.1'

        data_recv_mock.return_value=recv_data
        CacheOperate.unloads = MagicMock(return_value=[mmdata])
        pickle.dumps = MagicMock(return_value=message)

        with patch('builtins.print') as print_mock:
            self.command.cache(cmd)
            print_mock.assert_called_once_with(result)

    @patch('FlexiDNS.command.CacheOperate.data_recv')
    def test_03_history(self, data_recv_mock):

        cmd = {'history': {'all': True}}
        history_data = deque([(1712404645.3993819, '::1', DNSLabel(self.qname))], maxlen=500)
        data_recv_mock.return_value = {
            'type': None, 'argparse': None, 'data_length': 127, 'data': cpickle.dumps(history_data)}
        with patch('builtins.print') as print_mock:
            self.command.history(cmd)
            print_mock.assert_called()

if __name__ == '__main__':
    from os import _exit
    _exit(0)