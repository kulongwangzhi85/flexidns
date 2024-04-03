#!/usr/bin/env python3

# coding: utf-8

import unittest


class Test_DnsRules(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from FlexiDNS import dnsrules_new
        dnsrules_new.module_init()
        cls.rulesearch = dnsrules_new.rulesearch
        cls.iprepostitory = dnsrules_new.iprepostitory


    def tearDown(self):
        pass

    def setUp(self):
        self.rulesearch = Test_DnsRules.rulesearch
        self.iprepostitory = Test_DnsRules.iprepostitory

    def test_rules(self):
        pass


if __name__ == '__main__':
    from os import _exit
    _exit(0)
