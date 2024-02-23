
# coding: utf-8

"""
dns服务的域名缓存模块
NOTE: 缓存对象为qtype，并不是rtype
qtype：请求dns报文类型
rtype：返回dns报文类型
设计思路：客户端请求一个不存在的域名时，并且使用qtype为A记录。由于不存在该域名，此时返回的dns报文rtype为SOA。
"""

from collections import ChainMap
from os import path as ospath, _exit
from time import time
from types import MappingProxyType
from logging import getLogger

from dnslib import QTYPE, DNSRecord, QR, RR, A, AAAA, RCODE, DNSLabel
from IPy import IP

from .dnslog import dnsidAdapter
from .tomlconfigure import configs, share_objects
from .dnslrucache import LRUCache

logger = getLogger(__name__)
logger = dnsidAdapter(logger, {'dnsinfo': share_objects.contextvars_dnsinfo})

class MyChainMap(ChainMap):
    """
    由于cacheout.LRUCache类get()无法支持obj[x]方式，重載ChainMap中的get()方法
    以及添加add_many()与set_many()方法
    """
    __slots__ = ('result', 'index')

    def __init__(self, *maps) -> None:
        super().__init__(*maps)

        self.result = list()
        self.index = 0

    def __getitem__(self, key):
        self.result.clear()
        self.result.extend(filter(None, map(lambda i: i.get(key), self.maps)))
        if len(self.result) == 0:
            return None
        else:
            return self.result.pop()

    def get(self, key):
        return self.__getitem__(key)

    def __delitem__(self, key):
        for mapping in self.maps:
            if isinstance(mapping, LRUCache):
                mapping.delete(key)
            if isinstance(mapping, dict):
                mapping.pop(key, None)

    def __iter__(self):
        return self

    def __next__(self):
        if self.index < len(self.maps):
            result = self.maps[self.index]
            self.index += 1
            return result
        else:
            self.index = 0
            raise StopIteration

    def add_many(self, data):
        for key, value in data.items():
            self.maps[0].add_many({key: value})

    def set_many(self, data):
        for key, value in data.items():
            self.maps[0].set_many({key: value})


class lrucacheout:
    """域名缓存类，使用cacheout.LRUCache类实现互联网域名lru。静态域名使用dict
    字典缓存，使用pickle.dump()方法实现序列化

    search_cache: type: dict, 显式定义 chainmap_a_cache, chainmap_aaaa_cache, chainmap_https_cache, chainmap_soa_cache,常用dns请求类型
    在请求时，动态生成其它类型的dns缓存
    """
    __slots__ = (
        'configs',
        'a_cache',
        'aaaa_cache',
        'authority_cache',
        'static_a_cache',
        'static_aaaa_cache',
        'chainmap_a_cache',
        'chainmap_aaaa_cache',
        'search_cache',
        'https_cache',
        'chainmap_https_cache',
        'chainmap_soa_cache',
        'cachettl',
        'fakeipttl',
        'hoststtl',
        'static_a_ttl',
        'static_aaaa_ttl',
        'cache_a_ttl',
        'cache_aaaa_ttl',
        'cache_ttl',
        'cache_soa_ttl',
        'chainmap_a_ttl',
        'chainmap_aaaa_ttl',
        'chainmap_soa_ttl',
        'readonly_host_a_cache',
        'readonly_host_aaaa_cache'
    )

    def __init__(self, maxsize=configs.lru_maxsize):
        self.configs = configs
        self.a_cache = LRUCache(maxsize=maxsize)
        self.aaaa_cache = LRUCache(maxsize=maxsize)
        self.authority_cache = LRUCache(maxsize=maxsize)
        self.https_cache = LRUCache(maxsize=maxsize)
        self.static_a_cache = {}
        self.static_aaaa_cache = {}
        self.readonly_host_a_cache = MappingProxyType(self.static_a_cache)
        self.readonly_host_aaaa_cache = MappingProxyType(self.static_aaaa_cache)

        self.static_a_ttl = {}
        self.static_aaaa_ttl = {}
        self.cache_a_ttl = LRUCache(maxsize=maxsize)
        self.cache_aaaa_ttl = LRUCache(maxsize=maxsize)
        self.cache_soa_ttl = LRUCache(maxsize=maxsize)
        self.hoststtl = {}

        self.chainmap_a_cache = MyChainMap(self.a_cache, self.readonly_host_a_cache)
        self.chainmap_aaaa_cache = MyChainMap(self.aaaa_cache, self.readonly_host_aaaa_cache)
        self.chainmap_soa_cache = MyChainMap(self.authority_cache)
        self.chainmap_https_cache = MyChainMap(self.https_cache)

        self.chainmap_a_ttl = MyChainMap(self.cache_a_ttl, self.static_a_ttl)
        self.chainmap_aaaa_ttl = MyChainMap(self.cache_aaaa_ttl, self.static_aaaa_ttl)
        self.chainmap_soa_ttl = MyChainMap(self.cache_soa_ttl)

        # dns resources recode
        self.search_cache = {
            QTYPE.get(QTYPE.A): self.chainmap_a_cache,
            QTYPE.get(QTYPE.AAAA): self.chainmap_aaaa_cache,
            QTYPE.get(QTYPE.HTTPS): self.chainmap_https_cache,
            QTYPE.get(QTYPE.SOA): self.chainmap_soa_cache
        }

        # dns ttl cacheed
        self.cache_ttl = {
            QTYPE.get(QTYPE.A): self.chainmap_a_ttl,
            QTYPE.get(QTYPE.AAAA): self.chainmap_aaaa_ttl,
            QTYPE.get(QTYPE.HTTPS): self.chainmap_soa_ttl,
            QTYPE.get(QTYPE.SOA): self.chainmap_soa_ttl
        }
        # search_cache用于缓存dns报文，初始化时创建的记录类型就这三个。后续有新的记录类型则动态生成。
        # 如未自动生成新的记录缓存对象，会在请求类型时异常。
        # 缓存方法是使用qtype，而不是rtype

    def __getstate__(self):
        """用于pickle dump
        """
        pickledata = {}
        for k, v in self.search_cache.items():
            if len(v.maps[0]) > 0:
                pickledata[k] = v.maps[0].copy()
        return pickledata

    def __setstate__(self, data):
        """用于pickle load
        """
        self.__init__()
        for key, value in data.items():
            if (save_obj := self.search_cache.get(key)) is None:
                tmp_cache = MyChainMap(LRUCache(maxsize=self.configs.lru_maxsize))
                tmp_cache.add_many(value)
                save_obj = self.search_cache.fromkeys((str(key), ), tmp_cache)
                self.search_cache.update(save_obj)
            else:
                for k, v in value.items():
                    save_obj.maps[0].add_many({k: v})

    def setdata(self, dnspkg):
        logger.debug(f'set cache {dnspkg} rcode {RCODE.get(dnspkg.response_header.get_rcode())}')

        if (_save_obj := self.search_cache.get(QTYPE.get(dnspkg.q.qtype))) is not None:
            _tmp_data = _save_obj.get(dnspkg.q.qname)
            if _tmp_data is None:
                _save_obj.add_many({dnspkg.q.qname: {'rr': dnspkg.rr, 'auth': dnspkg.auth,'ar': dnspkg.ar, 'rcode': dnspkg.response_header.get_rcode()}})
            else:
                _save_obj.set_many({dnspkg.q.qname: {'rr': dnspkg.rr, 'auth': dnspkg.auth,'ar': dnspkg.ar, 'rcode': dnspkg.response_header .get_rcode()}})
        return

    def deldata(self, qname, qtype):
        logger.debug(f'del cache dnspkg, qname {qname} qtype {qtype}')
        if _save_obj := self.search_cache.get(QTYPE.get(qtype)):
            _tmp_data = _save_obj.get(qname)
            if _tmp_data:
                del _save_obj[qname]
                return

    def getdata(self, qname, qtype):
        """当未get到数据时，返回None。并fromkeys新qtype字典
        """

        if (_save_obj := self.search_cache.get(QTYPE.get(qtype))) is None:
            logger.debug(f'dnsrecord cache get: {_save_obj}')
            _save_obj = self.search_cache.fromkeys((QTYPE.get(qtype), ), MyChainMap(LRUCache(maxsize=self.configs.lru_maxsize)))
            self.search_cache.update(_save_obj)

        if _tmp_data := _save_obj.get(qname):
            return _tmp_data
        else:
            return None

    def set_static_data(self, pkg):
        """
        获取_hostcache为了可以让字段支持多个ip地址
        """

        if _hostcache := self.static_a_cache.get(pkg.q.qname):
            rr: list = _hostcache.get('rr')
            rr.extend(pkg.rr)
        else:
            self.static_a_cache.update({pkg.q.qname: {'rr': pkg.rr}})

    def set_static_data_v6(self, pkg):
        """
        获取_hostcache为了可以让字段支持多个ip地址
        """

        if _hostcache := self.static_aaaa_cache.get(pkg.q.qname):
            rr: list = _hostcache.get('rr')
            rr.extend(pkg.rr)
        else:
            self.static_aaaa_cache.update({pkg.q.qname: {'rr': pkg.rr}})
        return

    def setttl(self, qname, qtype, ttl, *args):
        '''
        通过args方法传递，设置ttl为静态域名，还是动态域名
        '''
        if self.configs.static_rule in args:
            match qtype:
                case "A":
                    self.static_a_ttl.update({qname: int(time()) + ttl})
                case "AAAA":
                    logger.debug(f'set ttl: {qname}, {ttl}, {args}')
                    self.static_aaaa_ttl.update({qname: int(time()) + ttl})
        else:
            logger.debug(f'set ttl: {qname}, {ttl}, {args}')

            if (_ttl_obj := self.cache_ttl.get(QTYPE.get(qtype))) is not None:
                _tmp_ttl = _ttl_obj.get(qname)
                logger.debug(f'set cache ttl in {_tmp_ttl}')
                if _tmp_ttl is None:
                    _ttl_obj.add_many({qname: int(time()) + ttl})
                else:
                    _ttl_obj.set_many({qname: int(time()) + ttl})
            else:
                _ttl_obj = self.search_cache.fromkeys((QTYPE.get(qtype), ), MyChainMap(LRUCache(maxsize=4096)))
                _tmp_ttl = _ttl_obj.get(QTYPE.get(qtype))
                _tmp_ttl.add_many({qname: int(time()) + ttl})
                self.cache_ttl.update(_ttl_obj)
                logger.debug(f'set _tmp_ttl in {_tmp_ttl}')
        return

    def getttl(self, qname, qtype, *args):
        if self.configs.static_rule in args:
            return self.configs.ttl_max

        if _ttl_obj := self.cache_ttl.get(QTYPE.get(qtype)):
            _tmp_ttl = _ttl_obj.get(qname)
            logger.debug(f'get cache ttl in _tmp_ttl: {_tmp_ttl}')
            if _tmp_ttl is None or _tmp_ttl <= 0:
                return self.configs.expired_reply_ttl
            else:
                _tmptime = _tmp_ttl - int(time())
                logger.debug(f'get cache ttl in _tmptime: {_tmptime}')
                if _tmptime >= self.configs.expired_reply_ttl:
                    return _tmptime
                else:
                    return self.configs.expired_reply_ttl
        else:
            return self.configs.expired_reply_ttl


def loader_static_domainname(static_domainname_set: dict):
    '''
    加载static_domainname_set集合到缓存，生成解析支持
    args:
        static_domainname_set:
        {
            'list': [
                '/path/static_domainname.txt'
            ],
            'domainname_v4': {
                'new.example.org': '192.168.3.3',
                'cloud.example.org':'192.168.3.30'
            },
            'domainname_v6': {
                'cloud.example.org':'2408:8248:480:31b8::1'
            }
        }

    list文件格式：
    <str:ipaddress> <str:domain>
    '''
    write_static_list_v4 = []
    write_static_list_v6 = []

    def write_to_cache(data: dict):
        _tmp_data = {}
        _tmp_data_6 = {}

        for domainname, ip in data.items():
            try:
                ip_object = IP(ip)
            except:
                continue
            if ip_object.version() == 4:
                _hostdns = _tmp_data.get(domainname)
                if _hostdns:
                    _hostdns.add_answer(
                        RR(domainname, ttl=configs.ttl_max, rtype=QTYPE.A, rdata=A(ip)))
                else:
                    q_host = DNSRecord.question(domainname)
                    _hostdns = q_host.reply()
                    _hostdns.add_answer(
                        RR(domainname, ttl=configs.ttl_max, rtype=QTYPE.A, rdata=A(ip)))
                    _tmp_data.update({domainname: _hostdns})
            if ip_object.version() == 6:
                _hostdns = _tmp_data_6.get(domainname)
                if _hostdns:
                    _hostdns.add_answer(
                        RR(domainname, ttl=configs.ttl_max, rtype=QTYPE.AAAA, rdata=AAAA(ip)))
                else:
                    q_host = DNSRecord.question(domainname, qtype="AAAA")
                    _hostdns = q_host.reply()
                    _hostdns.add_answer(
                        RR(domainname, ttl=configs.ttl_max, rtype=QTYPE.AAAA, rdata=AAAA(ip)))
                    _tmp_data_6.update({domainname: _hostdns})
        if len(_tmp_data.values()) > 0:
            for v in _tmp_data.values():
                new_cache.set_static_data(v)
                new_cache.setttl(
                    v.q.qname, 'A', configs.ttl_max, configs.static_rule)

        if len(_tmp_data_6.values()) > 0:
            for v in _tmp_data_6.values():
                new_cache.set_static_data_v6(v)
                new_cache.setttl(v.q.qname, 'AAAA',
                                 configs.ttl_max, configs.static_rule)

    if isinstance(static_lists := static_domainname_set.get('list'), list):
        for static_list in static_lists:
            if ospath.exists(static_list):
                with open(static_list, 'r') as fd:
                    for c in fd:
                        c = c.strip().lower().rstrip('\n')
                        if len(c) > 0 and not c.startswith('#'):
                            i = tuple(c.rstrip('\n').lower().split())
                            try:
                                ip_object = IP(i[0])
                            except:
                                continue
                            if ip_object.version() == 4:
                                write_static_list_v4.append({i[1]: i[0]})
                            if ip_object.version() == 6:
                                write_static_list_v6.append({i[1]: i[0]})

    if isinstance(static_lists := static_domainname_set.get('list'), str):
        if ospath.exists(static_lists):
            with open(static_lists, 'r') as fd:
                for c in fd:
                    c = c.strip().lower().rstrip('\n')
                    if len(c) > 0 and not c.startswith('#'):
                        i = tuple(c.rstrip('\n').lower().split())
                        try:
                            ip_object = IP(i[0])
                        except:
                            continue
                        if ip_object.version() == 4:
                            write_static_list_v4.append({i[1]: i[0]})
                        if ip_object.version() == 6:
                            write_static_list_v6.append({i[1]: i[0]})

    if static_domainnames_v4 := static_domainname_set.get('domainname_v4'):
        for k, v in static_domainnames_v4.items():
            c = k.strip().lower().rstrip('\n')
            write_static_list_v4.append({c: v})
    if static_domainnames_v6 := static_domainname_set.get('domainname_v6'):
        for k, v in static_domainnames_v6.items():
            c = k.strip().lower().rstrip('\n')
            write_static_list_v6.append({c: v})

    logger.debug(
        f'static domainname set: {write_static_list_v4}, v6 domainname set: {write_static_list_v6}')
    list(map(write_to_cache, write_static_list_v4))
    list(map(write_to_cache, write_static_list_v6))

new_cache = None

def module_init():
    global new_cache

    if configs.cache_persist and ospath.exists(configs.cache_file):
        from .dnspickle import deserialize
        new_cache = deserialize(lrucacheout.__name__)
        if new_cache is None:
            new_cache = lrucacheout()
            logger.debug('pickle data none or failed')
    else:
        new_cache = lrucacheout()

    loader_static_domainname(configs.static_domainname_set)


if __name__ == '__main__':
    _exit(0)
