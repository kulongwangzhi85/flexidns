
# coding: utf-8
"""
用于替换cacheout.LRUCache,因为高并发下使用asyncio会由于lock线程锁导致死锁
在运行中发现不知为什么使用OrderedDict，在操作move_to_end时CPU占用太多，因此使用deque代替OrderedDict作为LRU算法中的双端链表
"""

import typing as t
from logging import getLogger

logger = getLogger(__name__)

class ListNode:

    __slots__ = ('data', 'prev', 'next', 'key')
    def __init__(self, key=None, data=None):
        self.key = key
        self.data = data
        self.prev = None
        self.next = None

class LRUCache:

    maxsize: int
    cache: t.Dict[t.Hashable, ListNode]

    __slots__ = ('maxsize', 'cache', 'head', 'tail') 

    def __init__(self, maxsize: int = 256):
        """
        初始化一个LRUCache对象，初始两个虚拟节点，分别指向对方。
        这两个初始节点不作为数据节点使用，而是作为双向链表的头尾标签
        数据插入位置始终为head.next
        数据删除位置始终为tail.prev
        """
        self.maxsize = maxsize
        self.cache = {}
        self.head = ListNode()
        self.tail = ListNode()
        self.head.next = self.tail
        self.tail.prev = self.head

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({list(self.copy().items())})'

    def __getitem__(self, key: t.Hashable):
        return self.get(key)

    def __len__(self):
        return len(self.cache)

    def copy(self):
        """
        用于服务停止时的缓存持久化
        """
        cache = self.cache.copy()
        return dict((k, v.data) for k, v in cache.items())

    def set_many(self, kwargs: t.Hashable):
        for key, value in kwargs.items():
            self.set(key, value)

    def add_many(self, kwargs: t.Hashable):
        for key, value in kwargs.items():
            self.set(key, value)

    def __iter__(self):
        return iter(i.data for i in self.cache.values())

    def __next__(self):
        return next(iter(self.cache))

    def keys(self):
        return self.copy().keys()

    def add_node(self, node: ListNode):
        """
        将节点添加到双向链表的头部
        """
        node.prev = self.head
        node.next = self.head.next
        self.head.next.prev = node
        self.head.next = node

    def remove_node(self, node: ListNode):
        prev = node.prev
        new = node.next
        prev.next = new
        new.prev = prev

    def move_to_head(self, node: ListNode):
        self.remove_node(node)
        self.add_node(node)

    def pop_tail(self):
        tail = self.tail.prev
        self.remove_node(tail)
        return tail

    def get(self, key):
        if (node := self.cache.get(key, None)) is None:
            return None
        self.move_to_head(node)
        return node.data

    def set(self, key, value):
        if (node := self.cache.get(key, None)) is None:
            newNode = ListNode(key, value)
            self.cache[key] = newNode
            self.add_node(newNode)
            if len(self.cache) > self.maxsize:
                tail = self.pop_tail()
                self.cache.pop(tail.key, None)
        else:
            node.data = value
            self.move_to_head(node)

    def delete(self, key):
        if (node := self.cache.pop(key, None)) is not None:
            self.remove_node(node)


if __name__ == '__main__':
    from os import _exit
    _exit(0)