
# coding: utf-8

"""
命令行模块，实现在命令行模式下使用子命令完成对dns服务中缓存或规则的查询，修改，删除操作
NOTE：这里使用mmap与pipe同时使用，不用奇怪!主要学习为目的
"""

import base64
import mmap
import os
import pickle
from logging import getLogger

from .tomlconfigure import configs
from .tomlconfigure import share_objects

logger = getLogger(__name__)


class ManagerMmap:
    """管理MMAP,写入与读取数据
    mmaps: key -> fd, value -> mmap[index]
    目标实现：
    """

    def __init__(self):
        from .dnscache import new_cache
        self.new_cache = new_cache
        self.MMAPFILE = configs.mmapfile
        self.mm = self.__createmmap(1024)

    def __getattr__(self, name):
        if name == 'rulesearch':
            from .dnsrules_new import rulesearch
            setattr(self, name, rulesearch)
            return getattr(self, name)
        else:
            raise AttributeError(name)

    def __dir__(self):
        self.__getattr__('rulesearch')
        return dir(self)

    def __send_data(self, data):

        bytes_response_data = base64.b64encode(pickle.dumps(data))
        bytes_response_length = pickle.dumps(len(bytes_response_data))
        return bytes_response_length, bytes_response_data

    def __createmmap(self, size):
        fd = os.open(self.MMAPFILE, os.O_RDWR | os.O_CREAT, 0o666)
        os.write(fd, b'\x00' * size)
        mm = mmap.mmap(fd, size)
        os.close(fd)
        return mm

    def receving(self, command: bytes) -> bytes:
        cli_encode = pickle.loads(command)
        logger.debug(f'command decode: {cli_encode}')
        for i in cli_encode:
            match i:
                case 'rules':
                    return self.rules(cli_encode.get(i))
                case 'cache':
                    return self.cache(cli_encode.get(i))
                case 'history':
                    return self.history(cli_encode.get(i))

    def rules(self, command: dict) -> bytes:
        """用于域名对应的rule查询或修改

        Args:
            command (dict): 
            {
                "name": name,
                "rule": rule,
                "count": count,
                "show": show,
                "delete": delete
            }
            "name" = [('domain name', '<None: str> | <rule name>'), (...)]
            "rule" = "str"
            "count" = bool
            "show" = bool
            "delete" = [('domain name', '<None: str> | <rule name>'), (...)]

        Returns:
            _type_: bytes: data_length
            [('domain name', '<None> | <rule name>'), (...)]
        """
        logger.debug(f'received command {command}')

        if command.get('show'):
            command['show'] = list(configs.rulesjson.keys())
            logger.debug(f'rules: {command}')
            command['cmd'] = 'show'
            return pickle.dumps(command)

        if command.get('count'):
            command['count'] = len(self.rulesearch)
            logger.debug(f'rules count: {command}')
            command['cmd'] = 'count'
            return pickle.dumps(command)

        if command.get('rule'):
            logger.debug(f'command rule: {command}')
            rules_results = []
            for i in command.get('name'):
                if not i.endswith('.'):
                    i += '.'
                rules_results.append(self.rulesearch.modify(i, rule=command['rule']))
            data_length, data = self.__send_data(rules_results)
            logger.debug(f'received command {rules_results}')
            if len(data) > self.mm.size():
                self.mm.resize(len(data))
                self.mm.seek(0)
                self.mm.write(data)
                logger.debug('mmap write done')
            else:
                self.mm.seek(0)
                self.mm.write(data)
                logger.debug('mmap write done')
            command['rule'] = data_length
            command['cmd'] = 'rule'
            logger.debug(f'data: {command}')
            return pickle.dumps(command)

        if command.get('name'):
            # -n 选项
            rules_results = []
            for i in command['name']:
                if not i.endswith('.'):
                    i += '.'
                searchresutls = self.rulesearch.search(i, repositorie='upstreams-checkpoint')
                rules_results.append(
                    (i, 'static-rule' if searchresutls == configs.static_rule else searchresutls))

            data_length, data = self.__send_data(rules_results)
            logger.debug(f'received command {rules_results}')
            if len(data) > self.mm.size():
                self.mm.resize(len(data))
                self.mm.seek(0)
                self.mm.write(data)
                logger.debug('mmap write done')
            else:
                self.mm.seek(0)
                self.mm.write(data)
                logger.debug('mmap write done')
            command['name'] = data_length
            command['cmd'] = 'name'
            logger.debug(f'data: {command}')
            return pickle.dumps(command)

        if command.get('delete'):
            # 删除rule
            rules_results = []
            for i in command['delete']:
                if not i.endswith('.'):
                    i += '.'
                rules_results.append(self.rulesearch.delete(i))
            logger.debug(f'received command {rules_results}')
            command['cmd'] = 'delete'
            command['data'] = rules_results
            logger.debug(f'command {command}')
            return pickle.dumps(command)

    def cache(self, command: dict):
        from dnslib import DNSLabel
        logger.debug(f'received command {command}')

        match command.get('cmd'):
            case 'show':
                if command.get('all'):
                    datalist = self.new_cache
                elif command.get('qname'):
                    query_list = []
                    datalist = set()
                    for i in command.get('qname'):
                        query_list.append(DNSLabel(i))

                    for domain_name in query_list:
                        datalist_queryname = []
                        query_type = self.new_cache.search_cache.keys()
                        for k in query_type:
                            data = self.new_cache.getdata(domain_name, k)
                            if data:
                                datalist_queryname.append(data)

                        for i in datalist_queryname:
                            for k, y in i.items():
                                if isinstance(y, list) and len(y) > 0:
                                    for x in y:
                                        datalist.add(str(x))
                data_length, data = self.__send_data(datalist)

                if len(data) > self.mm.size():
                    # self.mm = self.__createmmap(len(data))
                    self.mm.resize(len(data))
                    self.mm.seek(0)
                    self.mm.write(data)
                    logger.debug('mmap write done')
                else:
                    self.mm.seek(0)
                    self.mm.write(data)
                    logger.debug('mmap write done')
                logger.debug(f'data length: {data_length}')
                return data_length

            case 'delete':
                # 删除非通配符域名
                logger.debug(f'delete command: {command}')
                delete_qnames = command.get('qname')
                for i in delete_qnames:
                    delete_qname = DNSLabel(i)
                    list(map(lambda x: self.new_cache.deldata(delete_qname, x), self.new_cache.search_cache.keys()))
                data_length, data = self.__send_data(True)
                self.mm.seek(0)
                self.mm.write(data)
                logger.debug('mmap write done')
                logger.debug(f'data length: {data_length} data: {data}')
                return data_length


    def history(self, command: dict) -> bytes:
        """用于域名对应的rule查询或修改

        args: {'history': {'all': True }}

        Returns:
            _type_: bytes: data_length
            [('domain name', '<None> | <rule name>'), (...)]
        """
        logger.debug(f'received command {command}')

        if command.get('all'):
            data_length, data = self.__send_data(share_objects.history)
            if len(data) > self.mm.size():
                self.mm.resize(len(data))
                self.mm.seek(0)
                self.mm.write(data)
                logger.debug('mmap write done')
            else:
                self.mm.seek(0)
                self.mm.write(data)
                logger.debug('mmap write done')
            logger.debug(f'data length: {data_length}')
            return data_length

commandmmap = ManagerMmap()

if __name__ == '__main__':
    os._exit(0)
