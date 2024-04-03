
# coding: utf-8

import sys
import os

sys.path.insert(0, project_rootpath := os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from FlexiDNS.tomlconfigure import loader_config
loader_config(os.path.join(project_rootpath, 'etc', 'flexidns', 'config_none.toml'))

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
"""
