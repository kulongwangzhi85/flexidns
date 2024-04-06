
# coding: utf-8

import unittest
from unittest.mock import Mock, patch

from FlexiDNS import dnslrucache

class Test_LruCache(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.lrucache = dnslrucache.LRUCache()
        cls.cache = {}

    def setUp(self) -> None:
        dnslrucache.logger = Mock()
        self.lrucache = Test_LruCache.lrucache
        self.key = 'flexidns'
        self.value = '127.0.0.1'
        self.key01 = 'flexidns01'
        self.value01 = '127.0.0.2'
        self.lrucache.cache = Test_LruCache.cache

    def test_01_slots(self):
        slots = ('maxsize', 'cache', 'head', 'tail')
        self.assertEqual(self.lrucache.__slots__, slots)
    
    def test_02_functions(self):
        dir = [
            'copy',
            'set_many',
            'add_many',
            'keys',
            'add_node',
            'remove_node',
            'move_to_head',
            'pop_tail',
            'get',
            'set',
            'delete',
            'cache',
            'head',
            'maxsize',
            'tail',
            '__repr__',
            '__getitem__',
            '__len__',
        ]

        for i in dir:
            self.assertIn(i, self.lrucache.__dir__())

    def test_03_set(self):
        self.lrucache.set(self.key, self.value)
        self.assertIn(self.key, self.cache)

    def test_04_get(self):
        with patch('FlexiDNS.dnslrucache.LRUCache.move_to_head'):
            self.assertEqual(self.lrucache.get(self.key), self.value)

    def test_05_delete(self):
        self.lrucache.delete(self.key)
        self.assertNotIn(self.key, self.cache)

    def test_06_set_many(self):
        self.lrucache.set_many({self.key: self.value, self.key01: self.value01})
        self.assertIn(self.key, self.cache)
        self.assertIn(self.key01, self.cache)

    def test_06_add_many(self):
        self.lrucache.add_many({self.key: self.value, self.key01: self.value01})
        self.assertIn(self.key, self.cache)
        self.assertIn(self.key01, self.cache)

