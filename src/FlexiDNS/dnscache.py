
# coding: utf-8

"""
dns服务的域名缓存模块
NOTE: 缓存对象为qtype，并不是rtype
qtype：请求dns报文类型
rtype：返回dns报文类型
设计思路：客户端请求一个不存在的域名时，并且使用qtype为A记录。由于不存在该域名，此时返回的dns报文rtype为SOA。
"""

from os import path as ospath, _exit
from time import time
from logging import getLogger
from typing import Any

from dnslib import QTYPE, DNSRecord, QR, RR, A, AAAA, RCODE, DNSLabel, DNSLabelError
from IPy import IP

from .dnslog import dnsidAdapter
from .dnstoml import configs, share_objects
from .dnslrucache import LRUCache

logger = getLogger(__name__)
logger = dnsidAdapter(logger, {'dnsinfo': share_objects.contextvars_dnsinfo})

class bimap:
    __slots__ = ('keys', 'values')

    def __init__(self):
        self.keys = dict()
        self.values = dict()

    def get(self, key):
        return self.keys.get(DNSLabel(key))

    def set(self, key, value):
        self.__setitem__(key, value)

    def pop(self, key):
        data = self.keys.pop(key, [])
        for i in data:
            self.values.pop(i, None)

    def __getitem__(self, key):
        return self.values.get(key)

    def __setitem__(self, key, value):
        if (data := self.keys.get(key, None)) is None:
            self.keys[key] = {value}
        else:
            data.add(value)
        self.values[value] = key

    def __getstate__(self) -> object:
        return {'keys': self.keys.copy(), 'values': self.values.copy()}

    def __setstate__(self, state):
        import copy
        setattr(self, 'keys', dict())
        setattr(self, 'values', dict())
        for k, v in state['keys'].items():
            if isinstance(v, list):
                _tmp_set = set()
                for name in v:
                    _tmp_set.add(str(name))
                self.keys[k] = copy.deepcopy(_tmp_set)
                _tmp_set.clear()
            else:
                self.keys[k] = v
        for k, v in state['values'].items():
            self.values[k] = v

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self.keys!r}, {self.values!r})'


class dnsttl:
    __slots__ = ('data',)
    def __init__(self, ttl=0):
        self.data = int(time()) + ttl

    def __repr__(self) -> str:
        return str(self.data)

    def __call__(self, *args: Any, **kwds: Any) -> int:
        return self.data - int(time())

class lrucacheout:
    """域名缓存类，使用cacheout.LRUCache类实现互联网域名lru。静态域名使用dict
    字典缓存，使用pickle.dump()方法实现序列化

    缓存结构：
    lrucache(dns 资源记录), dict(DNS记录)

    lrucache结构：
    {<DNS: Header>: { rr: [RR], ar: [AR], auth: [AUTH], rcode: int, ttl: timestamp}}

    search_cache: type: dict, 显式定义一些常用dns请求类型, 不常用的dns类型
    在请求时，动态生成其它类型的dns缓存
    """
    __slots__ = (
        'configs',
        'lru_maxsize',
        'static_rule',
        'cache_static',
        'a_cache',
        'aaaa_cache',
        'authority_cache',
        'static_a_cache',
        'static_aaaa_cache',
        'chainmap_a_cache',
        'chainmap_aaaa_cache',
        'search_cache',
        'https_cache',
        'cname',
    )

    def __new__(cls, *args, **kwargs):
        if not hasattr(cls, '__instance'):
            cls.__instance = super(lrucacheout, cls).__new__(cls)
        return cls.__instance

    def __init__(self, maxsize=share_objects.LRU_MAXSIZE):
        self.configs = configs
        self.lru_maxsize = share_objects.LRU_MAXSIZE
        self.static_rule = share_objects.STATIC_RULE
        self.cname = bimap()
        self.a_cache = LRUCache(maxsize=maxsize)
        self.aaaa_cache = LRUCache(maxsize=maxsize)
        self.authority_cache = LRUCache(maxsize=maxsize)
        self.https_cache = LRUCache(maxsize=maxsize)
        self.static_a_cache = {}
        self.static_aaaa_cache = {}

        # dns resources recode
        self.search_cache = {
            QTYPE.get(QTYPE.A): self.a_cache,
            QTYPE.get(QTYPE.AAAA): self.aaaa_cache,
            QTYPE.get(QTYPE.HTTPS): self.https_cache,
            QTYPE.get(QTYPE.SOA): self.authority_cache
        }

        self.cache_static = {
            QTYPE.get(QTYPE.A): self.static_a_cache,
            QTYPE.get(QTYPE.AAAA): self.static_aaaa_cache,
        }

        # search_cache用于缓存dns报文，初始化时创建的记录类型就这三个。后续有新的记录类型则动态生成。
        # 如未自动生成新的记录缓存对象，会在请求类型时异常。
        # 缓存方法是使用qtype，而不是rtype

    def __getstate__(self):
        """用于pickle dump
        """
        pickledata = {}
        for k, v in self.search_cache.items():
            if bool(v):
                pickledata[k] = v.copy()
        pickledata['cname'] = self.cname
        return pickledata

    def __setstate__(self, data):
        """用于pickle load
        """
        self.__init__()
        self.cname = data.pop('cname', bimap())
        for key, value in data.items():
            if (save_obj := self.search_cache.get(key)) is None:
                tmp_cache = LRUCache(maxsize=self.lru_maxsize)
                tmp_cache.add_many(value)
                save_obj = self.search_cache.fromkeys((str(key), ), tmp_cache)
                self.search_cache.update(save_obj)
            else:
                for k, v in value.items():
                    save_obj.add_many({k: v})

    def get_static(self, qname, qtype):
        if (save_obj := self.cache_static.get(QTYPE.get(qtype))):

            if static_data := save_obj.get(qname):
                logger.debug(f'get static dns record: {qname}, qtype {QTYPE.get(qtype)}')
                return static_data
        return None

    def setdata(self, dnspkg):

        if (save_obj := self.search_cache.get(QTYPE.get(dnspkg.q.qtype))) is not None:
            logger.debug(f'set cache {dnspkg} rcode {RCODE.get(dnspkg.response_header.get_rcode())}')
            tmp_data = save_obj.get(dnspkg.q.qname)
            if tmp_data is None:
                save_obj.add_many({
                    dnspkg.q.qname: {
                    'rr': dnspkg.rr,
                    'auth': dnspkg.auth,
                    'rcode': dnspkg.response_header.get_rcode(),
                    'ttl': dnsttl(dnspkg.a.ttl)
                    }
                })
            else:
                save_obj.set_many({
                    dnspkg.q.qname: {
                    'rr': dnspkg.rr,
                    'auth': dnspkg.auth,
                    'rcode': dnspkg.response_header.get_rcode(),
                    'ttl': dnsttl(dnspkg.a.ttl)
                    }
                })
        return

    def deldata(self, qname, qtype):
        logger.debug(f'delete cache qname {qname} qtype {QTYPE.get(qtype)}')
        if save_obj := self.search_cache.get(QTYPE.get(qtype)):
            save_obj.delete(qname)

    def getdata(self, qname, qtype):
        """当未get到数据时，返回None。并fromkeys新qtype字典
        """

        logger.debug(f'dnsrecord cache get: {qname} qtype {QTYPE.get(qtype)}')
        if (save_obj := self.search_cache.get(QTYPE.get(qtype))) is None:
            save_obj = self.search_cache.fromkeys((QTYPE.get(qtype), ), LRUCache(maxsize=self.lru_maxsize))
            self.search_cache.update(save_obj)

        if (tmp_data := save_obj.get(qname)) is not None:
            return tmp_data
        else:
            return None

    def set_static(self, pkg):
        logger.debug(f'setting static dns record: {pkg.q.qname}')
        if (save_obj := self.cache_static.get(QTYPE.get(pkg.q.qtype))) is None:
            save_obj = self.cache_static.fromkeys((QTYPE.get(pkg.q.qtype), ), dict())
            self.cache_static.update(save_obj)

        if hostcache := save_obj.get(pkg.q.qname):
            rr: list = hostcache.get('rr')
            rr.extend(pkg.rr)
        else:
            save_obj.update({pkg.q.qname: {'rr': pkg.rr}})
        return

    def set_cnamemap(self, qname, cname):
        self.cname.set(qname, str(cname))

    def get_cnamemap(self, qname):
        return self.cname.get(qname)

def write_to_cache(domainname, ips):
    _tmp_data = {}
    _tmp_data_6 = {}

    for ip in ips:
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
            new_cache.set_static(v)

    if len(_tmp_data_6.values()) > 0:
        for v in _tmp_data_6.values():
            new_cache.set_static(v)

def loader_static_domainname(static_domainname_set: dict):
    '''
    加载static_domainname_set集合到缓存，生成解析支持
    args:
        static_domainname_set:
        {
            4: {
                'new.example.org': ['192.168.3.3'],
                'cloud.example.org':['192.168.3.30']
            },
            6: {
                'cloud.example.org':['2408:8248:480:31b8::1]'
            }
        }
    '''

    if static_domainnames_v4 := static_domainname_set.get(4):
        logger.debug(f'static domainname v4: {static_domainnames_v4}')
        [write_to_cache(k, v) for k, v in static_domainnames_v4.items()]
    if static_domainnames_v6 := static_domainname_set.get(6):
        logger.debug(f'static domainname v6: {static_domainnames_v6}')
        [write_to_cache(k, v) for k, v in static_domainnames_v6.items()]


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
