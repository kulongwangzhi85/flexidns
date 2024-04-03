#!/usr/bin/env python3

# coding: utf-8

import unittest


class Test_DnsCache(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from FlexiDNS import dnscache
        dnscache.module_init()
        cls.new_cache = dnscache.new_cache


    def tearDown(self):
        pass

    def setUp(self):
        self.new_cache = Test_DnsCache.new_cache

    def test_function(self):
        pass


if __name__ == '__main__':
    from os import _exit
    _exit(0)
