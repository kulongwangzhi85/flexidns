
# coding: utf-8

import unittest
from collections import deque
from unittest.mock import patch, MagicMock, Mock

from dnslib import *

from FlexiDNS.command import CacheOperate, os


class Test_Command(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        os.path.exists = Mock(return_value=True)
        cls.command = CacheOperate()

    def setUp(self) -> None:
        self.command = Test_Command.command
        self.qname = 'www.flexidns.com'
        self.dnslabel = DNSLabel(self.qname)
        self.rr = RR(self.qname, ttl=60, rdata=A('192.168.1.1'))

    @patch('FlexiDNS.command.pickle.dumps')
    @patch('FlexiDNS.command.CacheOperate.data_recv')
    def test_01_cacheshow_dict(self, data_recv_mock, pickle_dumps_mock):
        import pickle as cpickle
        cmd = {'cache': {'cmd': 'show', 'all': True, 'qname': None}}
        message = cpickle.dumps(cmd)
        recv_data = {'type': 'cache', 'argparse': 'show', 'data_length': 30, 'data': b''}
        mmdata = {self.dnslabel: {'rr': [self.rr]}}
        result = '      www.flexidns.com.            60     IN     A      192.168.1.1'

        data_recv_mock.return_value=recv_data
        CacheOperate.unloads = MagicMock(return_value=[mmdata])
        pickle_dumps_mock.return_value=message

        with patch('builtins.print') as print_mock:
            self.command.cache(cmd)
            print_mock.assert_called_once_with(result)

    @patch('FlexiDNS.command.pickle.dumps')
    @patch('FlexiDNS.command.CacheOperate.data_recv')
    def test_02_cacheshow_list(self, data_recv_mock, pickle_dumps_mock):
        import pickle as cpickle
        cmd = {'cache': {'cmd': 'show', 'all': False, 'qname': [self.qname]}}
        message = cpickle.dumps(cmd)
        recv_data = {'type': 'cache', 'argparse': 'show', 'data_length': 30, 'data': b''}
        mmdata = [[self.rr]]
        result = '      www.flexidns.com.            60     IN     A      192.168.1.1'

        data_recv_mock.return_value=recv_data
        CacheOperate.unloads = MagicMock(return_value=[mmdata])
        pickle_dumps_mock.return_value=message

        with patch('builtins.print') as print_mock:
            self.command.cache(cmd)
            print_mock.assert_called_once_with(result)

class Test_Command_history(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        os.path.exists = Mock(return_value=True)
        cls.command = CacheOperate()

    def setUp(self) -> None:
        import pickle
        # 因为pickle在测试用例中，会被覆盖。所以在setUp中使用
        self.command = Test_Command_history.command
        self.qname = 'www.flexidns.com'
        self.dnslabel = DNSLabel(self.qname)
        self.rr = RR(self.qname, ttl=60, rdata=A('192.168.1.1'))
        self.history = deque([(1712404645.3993819, '::1', DNSLabel(self.qname))], maxlen=500)
        self.history_data = pickle.dumps(self.history)
        self.cmd = {'history': {'all': True}}

    @patch('FlexiDNS.command.pickle.loads')
    @patch('FlexiDNS.command.pickle.dumps')
    @patch('FlexiDNS.command.CacheOperate.data_recv')
    def test_03_history(self, data_recv_mock, pickle_dumps_mock, pickle_loads_mock):

        pickle_dumps_mock.return_value=None
        pickle_loads_mock.return_value=self.history

        data_recv_mock.return_value = {
            'type': None, 'argparse': None, 'data_length': 127, 'data': self.history_data}
        with patch('builtins.print') as print_mock:
            self.command.history(self.cmd)
            print_mock.assert_called()

if __name__ == '__main__':
    from os import _exit
    _exit(0)