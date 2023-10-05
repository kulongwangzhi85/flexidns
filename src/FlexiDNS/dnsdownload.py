
# coding: utf-8

# 该模块用于下载域名规则集
# 注意：域名集合格式，每一行为一个域名
# 域名集合使用 https://github.com/Loyalsoldier/v2ray-rules-dat下txt格式

import asyncio
import io
import sys


async def downloads(url):
    pass


def save_to_file(data, file_name):
    pass


if __name__ == '__main__':
    srcfile = '/tmp/proxy-list.txt'
    with open(srcfile, 'r') as f:
        for i in f.readlines():
            print(i.lstrip('full:'))
            print(i.startswith('full:'))
