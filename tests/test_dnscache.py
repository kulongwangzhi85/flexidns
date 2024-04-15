
# coding: utf-8

import unittest
from unittest.mock import Mock, MagicMock

from dnslib import *

from FlexiDNS import dnscache
from FlexiDNS.dnstoml import share_objects


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
        slots = (
            'configs',
            'lru_maxsize',
            'static_rule',
            'cache_static',
            'a_cache',
            'aaaa_cache',
            'authority_cache',
            'static_a_cache',
            'static_aaaa_cache',
            'chainmap_a_cache',
            'chainmap_aaaa_cache',
            'search_cache',
            'https_cache',
            'cname',
        )
        self.assertEqual(self.new_cache.__slots__, slots)

    def test_02_setdata(self):
        Test_DnsCache.dnspkg = DNSRecord()
        dnspkg_header = DNSHeader()
        Test_DnsCache.dnspkg.add_question(DNSQuestion('www.flexidns.com'))
        Test_DnsCache.dnspkg.add_answer(RR('www.flexidns.com', ttl=60, rdata=A('192.168.1.1')))
        Test_DnsCache.dnspkg.ttl = 60

        setattr(Test_DnsCache.dnspkg, 'response_header', dnspkg_header)
        self.new_cache.setdata(dnspkg=Test_DnsCache.dnspkg)

    def test_01_getdata_without_data(self):
        dnspkg = self.new_cache.getdata('www.flexidns.com', QTYPE.A)
        self.assertIsNone(dnspkg)

    def test_03_getdata_with_data(self):
        dnspkg = self.new_cache.getdata(Test_DnsCache.dnspkg.q.qname, QTYPE.A)
        self.assertEqual(dnspkg.get('rr')[0], Test_DnsCache.dnspkg.rr[0])

class Test_DnsCache_Funciton(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.new_cache = dnscache.lrucacheout(share_objects.LRU_MAXSIZE)
        cls.search_cache = MagicMock()
        cls.dnspkg = DNSRecord()
        dnspkg_header = DNSHeader()
        cls.dnspkg.add_question(DNSQuestion('www.flexidns.com'))
        cls.dnspkg.add_answer(RR('www.flexidns.com', ttl=60, rdata=A('192.168.1.1')))
        cls.dnspkg.ttl = 60
        setattr(cls.dnspkg, 'response_header', dnspkg_header)

    def setUp(self) -> None:
        dnscache.logger = Mock()
        self.new_cache = Test_DnsCache_Funciton.new_cache
        self.dnspkg = Test_DnsCache_Funciton.dnspkg
        self.new_cache.search_cache = Test_DnsCache_Funciton.search_cache

    def test_getdata(self):
        self.new_cache.setdata(self.dnspkg)

    def test_setdata(self):
        self.new_cache.getdata(self.dnspkg.q.qname, QTYPE.A)

if __name__ == '__main__':
    from os import _exit
    _exit(0)
