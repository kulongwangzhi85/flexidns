
# coding: utf-8
"""
用于替换cacheout.LRUCache,因为高并发下使用asyncio会由于lock线程锁导致死锁
在运行中发现不知为什么使用OrderedDict，在操作move_to_end时CPU占用太多，因此使用deque代替OrderedDict作为LRU算法中的双端链表
"""

from collections import deque
import typing as t
from logging import getLogger

logger = getLogger(__name__)

class LRUCache:

    maxsize: int
    cache: t.Dict[t.Hashable, t.List]
    access_order: t.Deque[t.Hashable]

    __slots__ = ('maxsize', 'cache', 'access_order') 

    def __init__(self, maxsize: int = 256):
        self.maxsize = maxsize
        self.cache = {}
        self.access_order = deque()

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({list(self.copy().items())})'

    def __getitem__(self, key: t.Hashable):
        return self.get(key)

    def __len__(self):
        return len(self.cache)

    def copy(self):
        return self.cache.copy()

    def set_many(self, kwargs: t.Hashable):
        for key, value in kwargs.items():
            self.set(key, value)

    def add_many(self, kwargs: t.Hashable):
        for key, value in kwargs.items():
            self.set(key, value)

    def __iter__(self):
        return iter(self.cache.values())

    def __next__(self):
        return next(iter(self.cache))

    def keys(self):
        return self.copy().keys()

    def move_to_end(self, key: t.Hashable):
        try:
            self.access_order.remove(key)
        except ValueError:
            logger.error(f'Key {key} not in cache')

        self.access_order.appendleft(key)

    def set(self, key: t.Hashable, value: t.List):
        if len(self.access_order) > self.maxsize:
            self.cache.pop(self.access_order.pop(), None)
        self.cache[key] = value
        self.access_order.appendleft(key)

    def get(self, key: t.Hashable) -> t.List:
        if (result := self.cache.get(key, None)) is not None:
            self.move_to_end(key) # 访问缓存数据将移至头部
        return result

    def delete(self, key: t.Hashable):
        try:
            self.cache.pop(key, None)
            self.access_order.remove(key)
        except (ValueError, KeyError):
            logger.error(f'Key {key} not in cache')


if __name__ == '__main__':
    from os import _exit
    _exit(0)