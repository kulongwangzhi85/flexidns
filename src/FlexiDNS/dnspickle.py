
# coding: utf-8

"""
使用pickle对dns服务中需要缓存对象
该模块将多个对象缓存进一个pickle文件中，在启动服务时，使用该文件进行加载还原

安全查找模块功能只允许导入本项目名相关的模块、dnslib第三方模块、以及部分内置方法
"""

import builtins
import pickle

from os import path, _exit
from logging import getLogger
from threading import local

from .__init__ import PACKAGE_NAME

logger = getLogger(__name__)
datapool = local()
datapool.data = {}

safe_modules = {
        PACKAGE_NAME,
        'dnslib'
}

safe_builtins = {
    'bytearray',
}

class SafeUnPickle(pickle.Unpickler):
    def find_class(self, module, name):
        logger.debug(f'pickle find module: {module}, name: {name}')
        if module.split('.')[0] in safe_modules:
            if module.startswith(PACKAGE_NAME):
                mod = __import__(module, fromlist=[name])
                return getattr(mod, name)
            elif module.startswith('dnslib'):
                mod = __import__(module, fromlist=[name])
                return getattr(mod, name)
        elif name in safe_builtins:
            return getattr(builtins, name)
        raise pickle.UnpicklingError(f'module: {module}, name: {name}')


def serialize(filename=None, *obj):
    if filename:
        cache_file = filename
    else:
        from .tomlconfigure import configs
        cache_file = configs.cache_file
    try:
        with open(cache_file, 'wb') as f:
            for i in obj:
                obj_id = i.__class__.__name__
                logger.debug(f'pickle serializing {obj_id}, obj {i}')
                pickle.dump((obj_id, i), f, pickle.HIGHEST_PROTOCOL)
    except PermissionError as e:
        logger.error(f'cannot write to cache file {e}')


def deserialize(obj_name=None):
    from .tomlconfigure import configs
    serialized_data = configs.cache_file
    logger.debug(f'pickle loading {obj_name}, datapool {datapool.data}')
    if path.exists(serialized_data):
        if datapool.data.get(obj_name, None) is None:
            with open(serialized_data, 'rb') as f:
                while True:
                    try:
                        obj_id, data = SafeUnPickle(f).load()
                        if data is not None:
                            datapool.data[obj_id] = data
                    except EOFError as e:
                        break
            return datapool.data.get(obj_name, None)
        else:
            return datapool.data.get(obj_name, None)


if __name__ == '__main__':
    _exit(1)
