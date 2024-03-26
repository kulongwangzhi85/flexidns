# 打包文件
# 打包完成后，可以使用命令查看包内容： python3 -m zipfile -l dist/xxx.whl
# 打包完成后，可以使用命令查看包元数据： pkginfo -f requires_dist  dist/xxx.whl

import sys
import os

from setuptools import setup

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

import FlexiDNS

setup()
