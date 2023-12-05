#!/usr/bin/env python3

# coding: utf-8

import unittest
import os
from multiprocessing.connection import Connection

from import_path import FlexiDNS, project_rootpath

class Shares_Ojbect_Tests:
    def __init__(self) -> None:
        from FlexiDNS.tomlconfigure import loader_config
        loader_config(os.path.join(project_rootpath, 'etc', 'flexidns', 'config_none.toml'))
        from FlexiDNS.tomlconfigure import configs, share_objects
        self.configs = configs
        self.share_object = share_objects


def create_test_suite():
    suite = unittest.TestSuite()
    suite.share_obj = Shares_Ojbect_Tests()
    suite.addTest(Test_TomlConfigure('test_read_configs'))
    suite.addTest(Test_TomlConfigure('test_vaild_path'))
    suite.addTest(Test_TomlConfigure('test_read_share_object'))
    return suite

class Test_TomlConfigure(unittest.TestCase):
    @classmethod
    def setupclass(cls):
        pass

    def setUp(self):
        self.configs = suite.share_obj.configs
        self.share_object = suite.share_obj.share_object

    def tearDown(self):
        pass

    def test_read_configs(self):
        self.assertIsInstance(self.configs.default_server, dict)
        self.assertIsInstance(self.configs.default_upstream_rule, str)
        self.assertIsInstance(self.configs.default_upstream_server, list)

        self.assertIsInstance(self.configs.timeout, float)
        self.assertIsInstance(self.configs.soa_list, set)
        self.assertIsInstance(self.configs.lru_maxsize, int)
        self.assertIsInstance(self.configs.static_rule, str)
        self.assertIsInstance(self.configs.default_rule, str)
        self.assertIsInstance(self.configs.sockfile, str)

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

    def test_configs_value(self):
        self.assertGreaterEqual(self.configs.lru_maxsize, 4096)

    def test_vaild_path(self):
        self.assertTrue(os.path.isabs(self.configs.cache_file))
        self.assertTrue(os.path.isabs(self.configs.logfile))
        self.assertTrue(os.path.isabs(self.configs.logerror))
        self.assertTrue(os.path.isabs(self.configs.sockfile))
        self.assertTrue(os.path.isabs(self.configs.pidfile))

        self.assertIn(self.configs.loglevel, ['debug', 'info', 'warning', 'error', 'critical'])
        self.assertGreater(self.configs.ttl_max, self.configs.ttl_min)
        self.assertGreater(self.configs.timeout, 1.0)

    def test_read_share_object(self):
        self.assertIsInstance(self.share_object.ttl_timeout_send, Connection)
        self.assertIsInstance(self.share_object.ttl_timeout_recv, Connection)
        self.assertIsInstance(self.share_object.ipc_mmap_size, int)
        self.assertGreater(self.share_object.ipc_mmap_size, 1024)

if __name__ == '__main__':
    suite = create_test_suite()
    runner = unittest.TextTestRunner()
    runner.run(suite)
