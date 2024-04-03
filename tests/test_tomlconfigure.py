
# coding: utf-8

import unittest
import os
from collections import deque
from multiprocessing.connection import Connection

from dnslib import *


class Test_TomlConfigure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from FlexiDNS.tomlconfigure import configs, share_objects
        cls.configs = configs
        cls.share_object = share_objects

    def setUp(self):
        self.configs = Test_TomlConfigure.configs
        self.share_object = Test_TomlConfigure.share_object

    def tearDown(self):
        pass

    def test_read_configs(self):
        self.assertIsInstance(self.configs.default_upstream_rule, str)
        self.assertIsInstance(self.configs.default_upstream_server, list)

        self.assertIsInstance(self.configs.timeout, float)
        self.assertIsInstance(self.configs.soa_list, set)
        self.assertIsInstance(self.share_object.LRU_MAXSIZE, int)
        self.assertIsInstance(self.share_object.STATIC_RULE, str)
        self.assertIsInstance(self.share_object.DEFAULT_RULE, str)
        self.assertIsInstance(self.share_object.SOCKFILE, str)

        self.assertIsInstance(self.configs.ttl_max, int)
        self.assertIsInstance(self.configs.ttl_min, int)
        self.assertIsInstance(self.configs.expired_reply_ttl, int)
        self.assertIsInstance(self.configs.fakeip_ttl, int)

        self.assertIsInstance(self.configs.logfile, str)
        self.assertIsInstance(self.configs.logerror, str)
        self.assertIsInstance(self.configs.loglevel, str)
        self.assertIsInstance(self.configs.logfile_size, int)
        self.assertIsInstance(self.configs.logfile_backupcount , int)

        self.assertIsInstance(self.configs.cache_persist, bool)
        self.assertIsInstance(self.configs.cache_file, str)

        self.assertIsNone(self.configs.edns0_ipv4_address)
        self.assertIsNone(self.configs.edns0_ipv6_address)
        self.assertIsInstance(self.share_object.BLACKLIST_MNAME, str)
        self.assertIsInstance(self.share_object.BLACKLIST_RNAME, str)
        self.assertIsInstance(self.share_object.history, deque)
        self.assertIsInstance(self.share_object.FAKEIP_NAME, str|None)
        self.assertIsInstance(self.configs.set_usage, list)
        self.assertIsInstance(self.configs.basedir, str|None)

    def test_configs_value(self):
        self.assertGreaterEqual(self.share_object.LRU_MAXSIZE, 4096)
        self.assertGreaterEqual(self.configs.ttl_max, self.configs.ttl_min)
        self.assertIsInstance(DNSLabel(self.share_object.BLACKLIST_MNAME), DNSLabel)
        self.assertIsInstance(DNSLabel(self.share_object.BLACKLIST_RNAME), DNSLabel)
        self.assertIn(self.configs.loglevel, self.share_object.LOGLEVELS)
        self.assertGreater(self.configs.ttl_max, self.configs.ttl_min)
        self.assertGreater(self.configs.timeout, 1.0)

    def test_vaild_path(self):
        self.assertTrue(os.path.isabs(self.configs.cache_file))
        self.assertTrue(os.path.isabs(self.configs.logfile))
        self.assertTrue(os.path.isabs(self.configs.logerror))
        self.assertTrue(os.path.isabs(self.share_object.SOCKFILE))
        self.assertTrue(os.path.isabs(self.share_object.PIDFILE))

    def test_read_share_object(self):
        self.assertIsInstance(self.share_object.ttl_timeout_send, Connection)
        self.assertIsInstance(self.share_object.ttl_timeout_recv, Connection)
        self.assertIsInstance(self.share_object.ipc_mmap_size, int)
        self.assertGreater(self.share_object.ipc_mmap_size, 1024)
        self.assertIsInstance(self.share_object.LOGDATEFMT, str)
        self.assertIsInstance(self.share_object.mmapfile, tuple)

if __name__ == '__main__':
    from os import _exit
    _exit(0)
