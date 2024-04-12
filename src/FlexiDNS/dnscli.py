
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

from dnslib import DNSLabel

from .dnstoml import configs, share_objects
from .dnspickle import serialize

logger = getLogger(__name__)


class ManagerMmap:
    """管理MMAP,写入与读取数据
    mmaps: key -> tempfile, value -> mmap[index]
    目标实现：
    """
    __slots__ = ('new_cache', 'rulesearch', 'MMAPFILE', 'mm', 'tempfile', 'rulesearch',)

    def __init__(self):
        from .dnscache import new_cache
        self.new_cache = new_cache
        from .dnsrules_new import rulesearch
        self.rulesearch = rulesearch
        self.MMAPFILE = share_objects.mmapfile
        self.mm, self.tempfile = self.__create_mmap(1024)

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

    def __data_serialization(self, data):
        bytes_response_data = pickle.dumps(data, protocol=pickle.HIGHEST_PROTOCOL)
        bytes_response_length = len(bytes_response_data)
        return bytes_response_length, bytes_response_data

    def __create_mmap(self, size):
        os.write(self.MMAPFILE[0], b'\x00' * size)
        mm = mmap.mmap(self.MMAPFILE[0], size)
        os.close(self.MMAPFILE[0])
        return mm, base64.b64encode(pickle.dumps(self.MMAPFILE[1]))

    def __write_mmap(self, data, data_length=0, append=False):
        if append:
            self.mm.resize(data_length)
            self.mm.write(data)
        else:
            self.mm.seek(0)
            if len(data) > self.mm.size():
                # self.mm = self.__create_mmap(len(data))
                self.mm.resize(len(data))
                self.mm.write(data)
            else:
                self.mm.write(data)

    def __response_data(self, *, command=None, argparse=None, data_length=0, data=None):
        """
        统一返回数据
        Args:
            data_length (int): 响应数据长度
            data (bytes): 响应数据
        Returns:
            {
                "type": "command name",
                "argparse": "argparse name",
                "data_length": data_length,
                "data": data
            }

            说明： data_length如果等于0，则表示data字段携带有效数据
            大于0，表示mmap对象数据长度, data字段携带mmap文件路径

            NOTE：mmap文件路径由tempfile.mkstemp生成

        """
        logger.debug(f'command: {command}, argparse: {argparse}, data_length: {data_length}, data: {data}')
        return {
            "type": command,
            "argparse": argparse,
            "data_length": data_length,
            "data": data if data is not None else self.MMAPFILE[1]
        }

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
            return self.__response_data(
                command='rules',
                argparse='show',
                data=list(configs.domainname_set.keys())
            )

        if command.get('count'):
            return self.__response_data(
                command='rules',
                argparse='count',
                data=len(self.rulesearch)
            )

        if command.get('rule'):
            logger.debug(f'command rule: {command}')
            rules_results = []
            for i in command.get('name'):
                if not i.endswith('.'):
                    i += '.'
                rules_results.append(self.rulesearch.modify(i, rule=command['rule']))
            data_length, data = self.__data_serialization(rules_results)
            logger.debug(f'received command {rules_results}')

            self.__write_mmap(data)

            return self.__response_data(
                command='rules',
                argparse='rule',
                data_length=data_length,
                data=self.tempfile
            )

        if command.get('name'):
            # -n 选项
            rules_results = []
            for i in command['name']:
                if not i.endswith('.'):
                    i += '.'
                searchresutls = self.rulesearch.search(i, repositorie='upstreams-checkpoint')
                rules_results.append(
                    (i, 'static-rule' if searchresutls == share_objects.STATIC_RULE else searchresutls))

            data_length, data = self.__data_serialization(rules_results)
            logger.debug(f'received command {rules_results}')

            self.__write_mmap(data)

            logger.debug(f'data length: {data_length}, tempfile: {self.tempfile}')
            return self.__response_data(
                command='rules',
                argparse='name',
                data_length=data_length,
                data=self.tempfile
            )

        if command.get('delete'):
            # 删除rule
            rules_results = []
            for i in command['delete']:
                rules_results.append(self.rulesearch.delete(i))
            logger.debug(f'received command {rules_results}')
            return self.__response_data(
                command='rules',
                argparse='delete',
                data=rules_results
            )

    def cache(self, command: dict):
        logger.debug(f'received command {command}')

        match command.get('cmd'):
            case 'show':
                if command.get('all'):
                    datalist = []
                    data_lengths = 0
                    self.mm.seek(0)
                    for value in self.new_cache.cache_static.values():
                        datalist.append(value.copy())
                    for value in self.new_cache.search_cache.values():
                        datalist.append(value.copy())
                    for i in datalist:
                        data_length, data = self.__data_serialization(i)
                        data_lengths += data_length
                        logger.debug(f'data length: {data_length}, data_lengths: {data_lengths}')
                        self.__write_mmap(data=data, data_length=data_lengths, append=True)

                    return self.__response_data(
                            command='cache',
                            argparse='show',
                            data_length=data_lengths,
                            data=self.tempfile
                            )
                elif command.get('qname'):
                    query_list = []
                    datalist_queryname = []
                    for i in command.get('qname'):
                        query_list.append(i)
                        query_list.extend(
                            result if isinstance(result := self.new_cache.get_cnamemap(i), set) else []
                            )
                    logger.debug(f'query list: {query_list}') 

                    for domain_name in query_list:
                        query_types = self.new_cache.search_cache.keys()
                        for qtype in query_types:
                            logger.debug(f'search qname {domain_name} qtype: {qtype}')
                            data = self.new_cache.getdata(DNSLabel(domain_name), qtype)
                            if data:
                                datalist_queryname.extend(data.values())
                            static_data = self.new_cache.get_static(DNSLabel(domain_name), qtype)
                            if static_data:
                                datalist_queryname.extend(static_data.values())
                    logger.debug(f'data: {datalist_queryname}')

                    data_length, data = self.__data_serialization(datalist_queryname)

                    self.__write_mmap(data)

                    logger.debug(f'data length: {data_length}, tempfile: {self.tempfile}')
                    return self.__response_data(
                        command='cache',
                        argparse='show',
                        data_length=data_length,
                        data=self.tempfile
                        )

            case 'delete':
                # 删除非通配符域名
                logger.debug(f'delete command: {command}')
                delete_qnames = command.get('qname')
                delete_list = []
                for i in delete_qnames:
                    qname = DNSLabel(i)
                    if (cname := self.new_cache.get_cnamemap(qname)) is not None:
                        delete_list.extend(cname)
                    delete_list.append(qname)

                logger.debug(f'delete list: {delete_list}')
                for delete_qname in delete_list:
                    self.new_cache.cname.pop(delete_qname)
                    list(
                        map(
                            lambda x: self.new_cache.deldata(delete_qname, x),
                            self.new_cache.search_cache.keys()
                            )
                        )

                data_length, data = self.__data_serialization(True)
                logger.debug(f'data length: {data_length} data: {data}')
                self.__write_mmap(data)

                return self.__response_data(
                    data_length=data_length,
                    data=self.tempfile
                    )

            case 'save':
                logger.debug(f'save command: {command}')

                if savefile := command.get('save'):
                    logger.debug(f'save command: {savefile}')
                    serialize(savefile, self.new_cache, self.rulesearch)

                elif configs.cache_file:
                    serialize(None, self.new_cache, self.rulesearch)

                data_length, data = self.__data_serialization(True)
                logger.debug(f'data length: {data_length} data: {data}')
                self.__write_mmap(data)

                return self.__response_data(
                    data_length=data_length,
                    data=self.tempfile
                    )
    def history(self, command: dict) -> bytes:
        """用于域名对应的rule查询或修改

        args: {'history': {'all': True }}

        Returns:
            _type_: bytes: data_length
            [('domain name', '<None> | <rule name>'), (...)]
        """
        logger.debug(f'received command {command}')

        if command.get('all'):
            data_length, data = self.__data_serialization(share_objects.history.copy())
            self.__write_mmap(data)
            logger.debug(f'data length: {data_length}')
            return self.__response_data(
                data_length=data_length,
                data=self.tempfile
                )

commandmmap = ManagerMmap()

if __name__ == '__main__':
    os._exit(0)
