
# coding: utf-8

import unittest
from unittest.mock import Mock, MagicMock, patch, PropertyMock

from dnslib import *

from FlexiDNS.dnsrules_new import RULESearch, RULERepository, ChainMapRule, IPRepostitory, module_init, logger

class Test_DnsRules(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rulesearch = RULESearch()

    def tearDown(self):
        pass

    def setUp(self):
        self.rulesearch = Test_DnsRules.rulesearch
        logger = MagicMock()
        self.rulename = 'default'
        self.name = 'www.flexidns.com'
        self.qname = DNSLabel(self.name)
        self.rulesearch.searchcache = MagicMock(spec=ChainMapRule)
        self.rulesearch.searchcache.set_many.return_value = None
        self.rulesearch.searchcache.maps = [dict(), dict()]

    def test_slots(self):
        __slots = (
            'searchcache',
            'customizerules',
            'upserver',
            'new_cache',
            'rulesfull',
            'static_rule',
            'ruleswildcard',
            'none_results',
            'upstream_cont',
            'rulesstatic',
            'resultlist',
            'default_rule',
            'configs',
        )
        self.assertTrue(hasattr(self.rulesearch, '__slots__'))
        self.assertEqual(self.rulesearch.__slots__, __slots)
    
    def test_funcition(self):
        __dir = [
            '__slots__',
            '__new__',
            '__init__',
            '__getstate__',
            '__setstate__',
            '__getattr__',
            'search',
            'modify',
            'back_search',
            'delete',
            '_RULESearch__delete_rulesfull_cache',
            '_RULESearch__delete_ruleswildcard_cache',
            'cname_map_qname',
            'configs',
            'customizerules',
            'default_rule',
            'new_cache',
            'none_results',
            'resultlist',
            'rulesfull',
            'rulesstatic',
            'ruleswildcard',
            'searchcache',
            'static_rule',
            'upserver',
            'upstream_cont',
            'daemon_write',
            'domainname_set',
            'repositories',
            'set_static_list',
            'set_usage',
            '__setattr__',
            '__len__'
            ] 
        for func in __dir:
            self.assertIn(func, __dir)

    def test_search(self):
        self.rulesearch.searchcache.get.return_value = self.rulename
        repositorie = 'upstreams-checkpoint'
        result = self.rulesearch.search(self.name, repositorie=repositorie)
        self.assertEqual(result, self.rulename)

    @patch('FlexiDNS.dnsrules_new.RULESearch.back_search')
    def test_search_01(self, back_search_mock: Mock):
        back_search_mock.return_value = self.rulename
        self.rulesearch.searchcache.get.return_value = None
        self.rulesearch.searchcache.add_many.return_value = None

        repositorie = 'upstreams-checkpoint'
        result = self.rulesearch.search(self.name, repositorie=repositorie)
        self.assertEqual(result, self.rulename)

    def test_modify(self):
        self.rulesearch.searchcache = MagicMock()
        self.rulesearch.searchcache.get.side_effect = lambda x: 'default' if x == self.rulename else 'proxy'
        self.rulesearch.new_cache = MagicMock()
        self.rulesearch.new_cache.search_cache.keys.return_value = ['A', 'AAAA']

        self.rulesearch.configs.domainname_set = {'default', 'proxy'}

        result = self.rulesearch.modify(self.name, rule='proxy')
        self.assertEqual(result[1], 'proxy')

class Test_Module_Init(unittest.TestCase):

    def setUp(self) -> None:
        logger = Mock()

    def test_init_without_pickle(self):

        with patch('FlexiDNS.dnsrules_new.RULESearch.__init__') as rulesearch_mock,\
              patch('FlexiDNS.dnsrules_new.IPRepostitory.__init__') as iprepostitory_mock, \
                patch('FlexiDNS.dnsrules_new.configs') as configs_mock:
            configs_mock.cache_persist = False
            configs_mock.cache_file = ''
            rulesearch_mock.return_value = None
            iprepostitory_mock.return_value = None

            module_init()
            rulesearch_mock.assert_called_once()
            iprepostitory_mock.assert_called_once()

    @patch('FlexiDNS.dnsrules_new.configs')
    def test_init_with_pickle(self, configs_mock):
        from FlexiDNS.dnspickle import deserialize

        with patch('FlexiDNS.dnsrules_new.RULESearch') as rulesearch_mock,\
              patch('FlexiDNS.dnsrules_new.IPRepostitory.__init__') as iprepostitory_mock, \
                patch('FlexiDNS.dnspickle.deserialize') as deserialize_mock, \
                    patch('FlexiDNS.dnsrules_new.ospath') as ospath_mock:

            rulesearch_mock.__name__ = 'RULESearch'
            ospath_mock.exists.return_value = True
            deserialize_mock.return_value = True
            configs_mock.cache_persist = True
            iprepostitory_mock.return_value = None

            module_init()
            iprepostitory_mock.assert_called_once()
            rulesearch_mock.assert_not_called()

if __name__ == '__main__':
    from os import _exit
    _exit(0)
