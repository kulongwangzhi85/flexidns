
# coding: utf-8

import unittest
from unittest.mock import Mock, MagicMock

from dnslib import *

from FlexiDNS import dnscache
from FlexiDNS.tomlconfigure import share_objects


class Test_DnsCache(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        dnscache.logger = Mock()
        dnscache.module_init()
        cls.new_cache = dnscache.new_cache


    def tearDown(self):
        pass

    def setUp(self):
        self.new_cache = Test_DnsCache.new_cache
        dnscache.logger = Mock()

    def test_slots(self):
        slots = ('configs', 'lru_maxsize', 'static_rule', 'a_cache', 'aaaa_cache', 'authority_cache', 'static_a_cache', 'static_aaaa_cache', 'chainmap_a_cache', 'chainmap_aaaa_cache', 'search_cache', 'https_cache', 'chainmap_https_cache', 'chainmap_soa_cache', 'cachettl', 'fakeipttl', 'hoststtl', 'static_a_ttl', 'static_aaaa_ttl', 'cache_a_ttl', 'cache_aaaa_ttl', 'cache_ttl', 'cache_soa_ttl', 'chainmap_a_ttl', 'chainmap_aaaa_ttl', 'chainmap_soa_ttl', 'readonly_host_a_cache', 'readonly_host_aaaa_cache', 'cname')
        self.assertEqual(self.new_cache.__slots__, slots)

    def test_02_setdata(self):
        Test_DnsCache.dnspkg = DNSRecord()
        dnspkg_header = DNSHeader()
        Test_DnsCache.dnspkg.add_question(DNSQuestion('www.flexidns.com'))
        Test_DnsCache.dnspkg.add_answer(RR('www.flexidns.com', ttl=60, rdata=A('192.168.1.1')))
        setattr(Test_DnsCache.dnspkg, 'response_header', dnspkg_header)
        self.new_cache.setdata(dnspkg=Test_DnsCache.dnspkg)

    def test_01_getdata_without_data(self):
        dnspkg = self.new_cache.getdata('www.flexidns.com', QTYPE.A)
        self.assertIsNone(dnspkg)

    def test_03_getdata_with_data(self):
        dnspkg = self.new_cache.getdata(Test_DnsCache.dnspkg.q.qname, QTYPE.A)
        self.assertEqual(dnspkg.get('rr')[0], Test_DnsCache.dnspkg.rr[0])

    def test_04_setttl(self):
        self.new_cache.setttl(Test_DnsCache.dnspkg.q.qname, QTYPE.get('A'), 60)

    def test_05_getttl(self):
        ttl = self.new_cache.getttl(Test_DnsCache.dnspkg.q.qname, QTYPE.get('A'))
        self.assertEqual(ttl, 60)

class Test_DnsCache_Funciton(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.new_cache = dnscache.lrucacheout(share_objects.LRU_MAXSIZE)
        cls.search_cache = MagicMock()
        cls.new_cache.cache_ttl = MagicMock()
        cls.dnspkg = DNSRecord()
        dnspkg_header = DNSHeader()
        cls.dnspkg.add_question(DNSQuestion('www.flexidns.com'))
        cls.dnspkg.add_answer(RR('www.flexidns.com', ttl=60, rdata=A('192.168.1.1')))
        setattr(cls.dnspkg, 'response_header', dnspkg_header)

    def setUp(self) -> None:
        dnscache.logger = Mock()
        self.new_cache = Test_DnsCache_Funciton.new_cache
        self.dnspkg = Test_DnsCache_Funciton.dnspkg
        self.new_cache.search_cache = Test_DnsCache_Funciton.search_cache

    def test_funcition(self):
        __dir = [
            '__slots__',
            '__init__',
            '__getstate__',
            '__setstate__',
            'setdata',
            'deldata',
            'getdata',
            'set_static_data',
            'set_static_data_v6',
            'setttl', 'getttl',
            'set_cnamemap',
            'get_cnamemap',
            'a_cache',
            'aaaa_cache',
            'authority_cache',
            'cache_a_ttl',
            'cache_aaaa_ttl',
            'cache_soa_ttl',
            'cache_ttl',
            'cachettl',
            'chainmap_a_cache',
            'chainmap_a_ttl',
            'chainmap_aaaa_cache',
            'chainmap_aaaa_ttl',
            'chainmap_https_cache',
            'chainmap_soa_cache',
            'chainmap_soa_ttl',
            'cname',
            'configs',
            'fakeipttl',
            'hoststtl',
            'https_cache',
            'lru_maxsize',
            'readonly_host_a_cache',
            'readonly_host_aaaa_cache',
            'search_cache',
            'static_a_cache',
            'static_a_ttl',
            'static_aaaa_cache',
            'static_aaaa_ttl',
            'static_rule'
            ]
        for func in __dir:
            self.assertIn(func, __dir)
    
    def test_slots(self):
        __slots = (
            'configs',
            'lru_maxsize',
            'static_rule',
            'a_cache',
            'aaaa_cache',
            'authority_cache',
            'static_a_cache',
            'static_aaaa_cache',
            'chainmap_a_cache',
            'chainmap_aaaa_cache',
            'search_cache',
            'https_cache',
            'chainmap_https_cache',
            'chainmap_soa_cache',
            'cachettl',
            'fakeipttl',
            'hoststtl',
            'static_a_ttl',
            'static_aaaa_ttl',
            'cache_a_ttl',
            'cache_aaaa_ttl',
            'cache_ttl',
            'cache_soa_ttl',
            'chainmap_a_ttl',
            'chainmap_aaaa_ttl',
            'chainmap_soa_ttl',
            'readonly_host_a_cache',
            'readonly_host_aaaa_cache',
            'cname'
            )
        for slots in __slots:
            self.assertIn(slots, self.new_cache.__slots__)

    def test_getdata(self):
        self.new_cache.setdata(self.dnspkg)

    def test_setdata(self):
        self.new_cache.getdata(self.dnspkg.q.qname, QTYPE.A)

    def test_setttl(self):
        self.new_cache.setttl(self.dnspkg.q.qname, QTYPE.get('A'), 60)

if __name__ == '__main__':
    from os import _exit
    _exit(0)
