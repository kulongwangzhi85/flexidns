
# coding: utf-8

import unittest
from os import path
from unittest.mock import patch, Mock, call

from flexidns import parse_arguments, start, historys, caches, rules, stop
from . import project_rootpath


class Test_FlexiDNS(unittest.TestCase):
    def setUp(self):
        self.command = path.join(project_rootpath, 'flexidns.py')
        self.configs = path.join(project_rootpath, 'etc', 'flexidns', 'config_none.toml')
        self.parse = parse_arguments()

    def test_start(self):
        self.assertTrue(self.parse.parse_args(['start', '-c', self.configs]))

    def test_stop(self):
        self.assertTrue(self.parse.parse_args(['stop']))

    def test_version(self):
        self.assertTrue(self.parse.parse_args(['version']))

    def test_history(self):
        self.assertTrue(self.parse.parse_args(['history']))

    def test_cacheshowall(self):
        self.assertTrue(self.parse.parse_args(['cache', 'show', '-a']))

    def test_cacheshow(self):
        self.assertTrue(self.parse.parse_args(['cache', 'show', '-n', 'www.flexidns.com']))

    def test_cachesave(self):
        self.assertTrue(self.parse.parse_args(['cache', 'save']))

    def test_rulesshow(self):
        self.assertTrue(self.parse.parse_args(['rules', '-n', 'www.flexidns.com']))

    def test_rulesdelete(self):
        self.assertTrue(self.parse.parse_args(['rules', '-d', 'www.flexidns.com']))

    def test_rulesshowcount(self):
        self.assertTrue(self.parse.parse_args(['rules', '-c']))

    def test_rulesshowname(self):
        self.assertTrue(self.parse.parse_args(['rules', '-s']))

    def test_rulesshowmodify(self):
        self.assertTrue(self.parse.parse_args(['rules', '-n', 'www.flexidns.com', '-r', 'default']))

    @patch('FlexiDNS.dnsmain.main')
    def test_start_funcions(self, main_mock: Mock):

        args = Mock(config=self.configs)

        start(args)
        main_mock.assert_called_once_with(args.config)

    def test_history_funcions(self):
        args = Mock(all='all')

        with patch('FlexiDNS.command.CacheOperate') as history_mock:
            historys(args)
            history_mock.assert_has_calls([call(), call().history({'history': {'all': 'all'}})])
            # assert_has_calls() 断言调用循序，第一次call()为historys()方法实例化，第二次call()为history()方法调用
            # 技巧：不知道列表中应该写什么时，可以使用assert_has_calls('asdf')错误值，调试时会打印出顺序
            # 注意：建议不要使用history_mock.assert_called_once_with(), 因为实例化时,就时调用一次。所以始终为正确。传入参数空值，无法验证参数
            # 注意：assert_has_calls([]),给空列表会忽略内部所有参数

    def test_stop_funcions(self):
        with patch('FlexiDNS.dnsmain.stop_server') as stop_mock:
            args = None
            stop(args)
            stop_mock.assert_called()

    def test_caches_funcions_show_all(self):

        args = Mock(all=True, show_qname=None)

        with patch('FlexiDNS.command.CacheOperate') as cache_mock:
            caches(args)
            cache_mock.assert_has_calls([call(), call().cache({'cache': {'cmd': 'show', 'all': True, 'qname': None}})])

