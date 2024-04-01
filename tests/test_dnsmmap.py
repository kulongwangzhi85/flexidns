#!/usr/bin/env python3

# coding: utf-8

import unittest
import os
from array import array

from . import project_rootpath


class Test_mmap(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from FlexiDNS.tomlconfigure import loader_config, share_objects
        loader_config(os.path.join(project_rootpath, 'etc', 'flexidns', 'config_devel.toml'))
        from FlexiDNS.dnsmmap_ipc import CircularBuffer

        cls.dnsmmap = CircularBuffer(share_objects.ipc_mmap, share_objects.ipc_mmap_size)
        cls.example_by_write_data = bytearray(b'1234567890abcdef')
        cls.__data_amount = None

    def tearDown(self):
        pass

    def setUp(self):
        self.data_amount = array('I', [0, 0, 16])

    def test_function(self):
        func = Test_mmap.dnsmmap.__dir__()
        self.assertIn('mm', func)
        self.assertIn('size', func)
        self.assertIn('locations', func)
        self.assertIn('read', func)
        self.assertIn('write', func)

    def test_01_write_data(self):
        Test_mmap.__data_amount = Test_mmap.dnsmmap.write(Test_mmap.example_by_write_data)
        self.assertIsInstance(self.data_amount, array)
        self.assertEqual(Test_mmap.__data_amount, self.data_amount)

    def test_02_read_data(self):
        data = Test_mmap.dnsmmap.read(self.data_amount)
        self.assertEqual(data, Test_mmap.example_by_write_data)

if __name__ == '__main__':
    from os import _exit
    _exit(0)
