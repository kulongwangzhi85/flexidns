
# coding: utf-8

import sys
import os
import logging
import time
from cacheout import LRUCache

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '/src/')

from pydns.tomlconfigure import loader_config
loader_config('/home/guocl/Python/proj002/src/etc/pydns/config_devel.toml')

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s %(name)s %(levelname)s %(lineno)s %(message)s",
                    datefmt='%Y-%m-%d  %H:%M:%S %a'  # 注意月份和天数不要搞乱了，这里的格式化符与time模块相同
                    )

from pydns.dnslrucache import LRUCache

lrucache = LRUCache(3)

def cache_test():
    lrucache.add_many({'www.baidu.com': ['127.0.0.1', '127.0.0.2']})
    lrucache.get('www.baidu.com')
    lrucache.set('www.google.com', ['127.0.0.1', '127.0.0.2'])
    lrucache.get('www.google.com')
    lrucache.set('www.youku.com', ['127.0.0.1', '127.0.0.2'])
    lrucache.get('www.youku.com')
    lrucache.get('www.baidu.com')
    lrucache.set('www.youtobe.com', ['127.0.0.1', '127.0.0.2'])
    lrucache.get('www.youtobe.com')
    lrucache['www.youtobe.com']
    print(lrucache.cache)
    lrucache.set('www.baidu.com', ['192.168.2.100'])
    print(lrucache.cache)
    lrucache.delete('www.baidu.com')
    print(lrucache.cache)

cache_test()