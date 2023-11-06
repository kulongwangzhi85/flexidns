
# coding: utf-8

"""
命令行模块，实现在命令行模式下使用子命令完成对dns服务中缓存或规则的查询，修改，删除操作
NOTE：这里使用mmap与pipe同时使用，不用奇怪!主要学习为目的
"""

import base64
import mmap
from math import ceil
import os
import pickle
import struct
from logging import getLogger

from .tomlconfigure import configs

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

    def __serialization(self, alist):
        """将cache序列化为list别表
        """
        data_container = set()

        for aa in filter(None, alist.values()):
            for bb in filter(None, aa.values()):
                for c, cc in filter(None, bb.items()):
                    if c != 'ar':
                        if isinstance(cc, int):
                            continue
                        for i in cc:
                            data_container.add(str(i))
        return data_container

    def __send_data(self, data):
        BASE_SIZE = [65535,]
        ''' 此处使用struct封装后，向客户端socket发送数据
        struct结构：
    
        1、2 bytes: 固定2字节长度
        作用：携带的数据为，第二部分跟随的数据长度边界
        内容：整数值，可容纳整数范围根据struct格式字符，这里使用H，占用2字节，可包含0-65535整数值
        含义：n个格式字符，例如3,这样也就知道跟随的数据有3个H，每个H，2个字节
    
        2、2-x bytes： 不固定字节长度
        作用：携带的数据为，数据长度
        内容：n个H，n由第一步携带数据获得。例如3H，struct数据内容根据根据实际数据长度65535, 65535, 1024，客户端使用sum()方法即可知道数据的完整长度
    
        3、x-x bytes:  不固定定字节长度 作用：数据本体
        注意：由于第一个2bytes使用固定长度，因此只能容纳0-65535，也就是说明第二个报文内只能容纳65536个H，因此该方法最大只支持4GiB大小的数据传输
        改进：未来如果需要传输大于4GiB的数据，可以将第二部分的struct格式字符由H修改为c，使用字符串方法传递数据长度
    
        '''
        bytes_response_data = base64.b64encode(pickle.dumps(data))
        # bytes_response_data = base64.b64encode(bytes(str(data), 'utf-8'))
        bytes_response_command_length = len(bytes_response_data)
        struct_length_step = ceil(bytes_response_command_length / 65535)
        struct_pack_length_count = struct.pack('!H', struct_length_step)

        struct_length_fmt = f'!{struct_length_step}H'
        if bytes_response_command_length > 65535:
            base_size = BASE_SIZE * (bytes_response_command_length // 65535)
            base_size.append(bytes_response_command_length % 65535)

            data_pack_length = struct.pack(struct_length_fmt, *base_size)
        else:
            data_pack_length = struct.pack(
                struct_length_fmt, bytes_response_command_length)

        # data_length = struct_pack_length_count + data_pack_length
        # b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xc8T'
        return data_pack_length, bytes_response_data

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
            logger.debug(f'data: {command}')
            command['cmd'] = 'name'
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
                    datalist = self.__serialization(
                        self.new_cache.search_cache)
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
                from dnslib import QTYPE, DNSLabel
                logger.debug(f'delete command: {command}')
                delete_result = set()
                delete_qnames = command.get('qname')
                for i in delete_qnames:
                    delete_qname = DNSLabel(i)
                    logger.debug(delete_qname)
                    self.new_cache.deldata(delete_qname, QTYPE.A)
                    self.new_cache.deldata(delete_qname, QTYPE.AAAA)
                    delete_result.add(self.new_cache.getdata(delete_qname, QTYPE.A))
                    delete_result.add(self.new_cache.getdata(delete_qname, QTYPE.AAAA))
                data_length, data = self.__send_data(delete_result)
                self.mm.seek(0)
                self.mm.write(data)
                logger.debug('mmap write done')
                logger.debug(f'delete result: {delete_result}, data length: {data_length} data: {data}')
                return data_length


commandmmap = ManagerMmap()

if __name__ == '__main__':
    os._exit(0)
