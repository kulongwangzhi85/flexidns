
# coding: utf-8

import sys
import os

sys.path.insert(0, project_rootpath := os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from FlexiDNS.dnstoml import loader_config, share_objects
loader_config(os.path.join(project_rootpath, 'etc', 'flexidns', 'config_none.toml'))


if os.path.exists(share_objects.PIDFILE):

    with open(share_objects.PIDFILE, 'r') as f:
        try:
            PGID = os.getpgid(int(f.read()))
        except (OSError, ProcessLookupError, ValueError):
            if os.path.exists(share_objects.SOCKFILE):
                os.remove(share_objects.SOCKFILE)
            os.remove(share_objects.PIDFILE)
else:
    if os.path.exists(share_objects.SOCKFILE):
        os.remove(share_objects.SOCKFILE)

"""
单元测试笔记

模块顺序:

使用discover方法测试tests包下所有测试模块时,会搜索模块名test_*.py
搜索执行顺序由内置字符串排序方法对测试名进行排序的结果决定

example:

test_01*.py -> test_dnscache.py -> test_dnsmmap.py -> test_tommconfigure.py -> test_*.py

测试用例顺序:

测试用例顺序同样遵循字符串顺序

全局变量：

使用discover方法时，全局变量在所有测试模块中可调用
本项目中在测试时，需要初始化configs，share_objects对象。在每个测试模块中都需要该对象时。
可以在__init__.py文件中初始化完成
如果在每个测试模块中初始化，会重复初始化对象

测试方法：

在项目根目录执行
NOTE: 不是tests目录内
python3 -m unittest discover -s . -p test_*.py
or
python3 -m unittest

tests/utest.py可以不需要该模块，如果有该模块并可以用于定制测试报告

Mock:

使用unittest.mock.Mock()来模拟对象，包括对象属性，以及对象内方法

模拟属性时，有些属性只保存着bool值或字符串，此时使用mock时，就不要使用return_value
例如：
myconfigs = mock.Mock()
myconfigs.status = True
说明：如果使用return_value来定义返回值，在使用使用就是調用，类似函数的调用,就是myconfigs.status(),才能获取

mock方法

return_value: 返回固定的值，也就是在单元测试中无论调用多少次都是该值
side_effect: 可以定义返回不同值，在某些测试中，需要对某个对象需要使用多次，当返回的值发生变化时可以使用该方法定义

例如：

self.rulesearch.searchcache.get.side_effect = lambda x: 'default' if x == self.rulename else 'proxy'

Mock统计:
called：当mock对象获得工厂调用时，访问器called返回True，否则返回False
call_count：返回mock对象被工厂调用的次数
call_args：返回工厂调用最近使用的参数
call_args_list：返回一个列表，包含所有使用的参数，第一项为最早的参数
mothod_calls：报告了测试对象所做的mock方法的调用。它的结果是一个列表，只显示方法调用，不显示工厂调用
mock_calls：报告了测试对象对mock对象所有的调用。结果是一个列表，工厂调用和方法调用都显示了

MagicMock:
在需要模拟遍历对象时，也就是__iter__、__next__、__getitem__等方法时，可以使用MagicMock

由于不是专业程序员，先学这么多吧。后面用到再学其它
"""
