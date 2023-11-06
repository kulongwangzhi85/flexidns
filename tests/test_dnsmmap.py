#!/usr/bin/env python3

# coding: utf-8

import unittest
import os
from import_path import FlexiDNS, project_rootpath

class Shares_Ojbect_Tests:
    def __init__(self) -> None:
        from FlexiDNS.tomlconfigure import loader_config, share_objects
        loader_config(os.path.join(project_rootpath, 'etc', 'flexidns', 'config_devel.toml'))
        from FlexiDNS.dnsmmap_ipc import CircularBuffer

        self.dnsmmap = CircularBuffer(share_objects.ipc_mmap, share_objects.ipc_mmap_size)
        self.example_by_write_data = bytearray(b'1234567890abcdef')
        self.data_amount = []


def create_test_suite():
    suite = unittest.TestSuite()
    suite.share_obj = Shares_Ojbect_Tests()
    suite.addTest(Test_MMap('test_datalocation'))
    suite.addTest(Test_MMap('test_read_dataamount'))
    suite.addTest(Test_MMap('test_write_data'))
    suite.addTest(Test_MMap('test_read_data'))
    return suite

class Test_MMap(unittest.TestCase):
    @classmethod
    def setupclass(cls):
        pass

    def tearDown(self):
        pass

    def test_datalocation(self):
        """
        测试 __data_location()方法
        example_by_write_data = bytearray(b'12345678
        """

        suite.share_obj.data_amount = suite.share_obj.dnsmmap.locations.send(len(suite.share_obj.example_by_write_data))
        self.assertListEqual(suite.share_obj.data_amount, [0, (0, 16)])

    def test_write_data(self):
        suite.share_obj.data_amount = suite.share_obj.dnsmmap.write(suite.share_obj.example_by_write_data)

    def test_read_dataamount(self):
        self.assertListEqual(suite.share_obj.data_amount, [0, (0, 16)])

    def test_read_data(self):
        data = suite.share_obj.dnsmmap.read(suite.share_obj.data_amount)
        self.assertEqual(data, suite.share_obj.example_by_write_data)

if __name__ == '__main__':
    suite = create_test_suite()
    runner = unittest.TextTestRunner()
    runner.run(suite)
