
# coding: utf-8

"""
域名和IP地址集合的加载，缓存，查询模块
该模块可以使用tests/rules-test.py进行测试与调试
"""

from array import array
from copy import deepcopy
from collections import ChainMap
from os import path as ospath, _exit
from logging import getLogger
from functools import reduce

from dnslib import DNSLabel
from IPy import IP

from .tomlconfigure import configs, share_objects
from .dnslog import dnsidAdapter
from .dnslrucache import LRUCache
from .dnspickle import deserialize

logger = getLogger(__name__)
logger = dnsidAdapter(logger, {'dnsinfo': share_objects.contextvars_dnsinfo})


class ChainMapRule(ChainMap):
    """
    由于cacheout.LRUCache类get()无法支持obj[x]方式，重載ChainMap中的get()方法
    以及添加add_many()与set_many()方法
    """

    def __parallel_search(self, customizerules, rulesfull, ruleswildcard, rulesstatic, key):
        if (result := customizerules.get(key)) or (result := rulesfull.get(key)) or (result := rulesstatic.get(key)) or (result := rulesearch.back_search(key, ruleswildcard)):
            return result

    def __getitem__(self, key):
        result = set(
            filter(None, map(lambda customizerules, rulesfull, ruleswildcard, rulesstatic: self.__parallel_search(customizerules, rulesfull, ruleswildcard, rulesstatic, key), [self.maps[0]], [self.maps[1]], [self.maps[2]], [self.maps[3]])))
        if len(result) == 0:
            return None
        else:
            return result.pop()

    def get(self, key):
        return self.__getitem__(key)

    def add_many(self, data):
        for key, value in data.items():
            self.maps[1].add_many({key: value})

    def set_many(self, data):
        self.add_many(data)

    def __delitem__(self, key):
        for mapping in self.maps:
            if key in mapping:
                if isinstance(mapping, LRUCache):
                    mapping.delete(key)
                    return True
                if isinstance(mapping, dict):
                    mapping.pop(key)
                    return True
        return None

class RULERepository:
    """处理domain-set加载到self.repositories中
    处理ip-set加载到self.repositories中
    """

    __slots__ = (
        'domainname_set',
        'default_rule',
        'static_rule',
        'set_usage',
        'repositories',
        'set_static_list'
    )

    def __init__(self):
        self.domainname_set = configs.domainname_set
        self.default_rule = configs.default_rule
        self.static_rule = configs.static_rule
        self.set_usage = configs.set_usage[0]

        normalpriority_dataclass = {}
        highpriority_dataclass = {}

        self.repositories = {
            'upstreams-checkpoint': {},
            'ip-sets-checkpoint': {}
        }
        # repositories: {'com': {'baidu': {'www': {'default-rule': 'cn'}, 'teiba':{'default-rule': 'cn'}}},...}
        # 用于存放配置文件中配置的域名集合，数量会多余self.ruleswildcard。测试时二十万左右条域名
        # 不可持久化缓存，规则由服务启动时加载生成

        for set_name in self.set_usage.get('domain-set').get('upstreams').keys():
            normalpriority_dataclass[set_name] = set()

            highpriority_dataclass[set_name] = set()

            value = self.domainname_set.get(set_name).get('list')
            # 处理域名集合
            if isinstance(value, list):
                for path_with_filename in value:
                    if ospath.exists(path_with_filename):
                        with open(path_with_filename, 'r') as f:
                            tmp_list = normalpriority_dataclass.get(set_name)
                            for c in f:
                                if c.startswith('regexp:'):
                                    # 未支持正则
                                    continue
                                c = c.strip().lower().replace('full:', '', 1).rstrip('\n')
                                # 由于该域名列表来自v2ray中的txt部分，列表中有full：开头与regexp开头
                                if len(c) > 0 and not c.startswith('#'):
                                    tmp_list.add(c)
            elif isinstance(path_with_filename := value, str):
                if ospath.exists(path_with_filename):
                    with open(path_with_filename, 'r') as f:
                        tmp_list = normalpriority_dataclass.get(set_name)
                        for c in f:
                            if c.startswith('regexp:'):
                                # 未支持正则
                                continue
                            c = c.strip().lower().replace('full:', '', 1).rstrip('\n')
                            if len(c) > 0 and not c.startswith('#'):
                                tmp_list.add(c)
            value = self.domainname_set.get(set_name).get('domainname')
            if value:
                tmp_list = highpriority_dataclass.get(set_name)
                # 配置文件中的域名将覆盖列表中的域名规则
                for domainname in value:
                    tmp_list.add(domainname)

        for set_name in self.set_usage.get('domain-set').get('blacklist').keys():

            normalpriority_dataclass[set_name] = set()

            highpriority_dataclass[set_name] = set()

            value = self.domainname_set.get(set_name).get('list')
            # 处理域名集合
            if isinstance(value, list):
                for path_with_filename in value:
                    if ospath.exists(path_with_filename):
                        with open(path_with_filename, 'r') as f:
                            tmp_list = normalpriority_dataclass.get(set_name)
                            for c in f:
                                if c.startswith('regexp:'):
                                    # 未支持正则
                                    continue
                                c = c.strip().lower().replace('full:', '', 1).rstrip('\n')
                                # 由于该域名列表来自v2ray中的txt部分，列表中有full：开头与regexp开头
                                if len(c) > 0 and not c.startswith('#'):
                                    tmp_list.add(c)
            elif isinstance(path_with_filename := value, str):
                if ospath.exists(path_with_filename):
                    with open(path_with_filename, 'r') as f:
                        tmp_list = normalpriority_dataclass.get(set_name)
                        for c in f:
                            if c.startswith('regexp:'):
                                # 未支持正则
                                continue
                            c = c.strip().lower().replace('full:', '', 1).rstrip('\n')
                            if len(c) > 0 and not c.startswith('#'):
                                tmp_list.add(c)
            value = self.domainname_set.get(set_name).get('domainname')
            if value:
                tmp_list = highpriority_dataclass.get(set_name)
                # 配置文件中的域名将覆盖列表中的域名规则
                for domainname in value:
                    tmp_list.add(domainname)

        if len(normalpriority_dataclass) > 0:
            for k, v in normalpriority_dataclass.items():
                self.daemon_write(
                    domainname_list=v,
                    rulename=k,
                    cache_object=self.repositories['upstreams-checkpoint']
                )

        if len(highpriority_dataclass) > 0:
            for k, v in highpriority_dataclass.items():
                self.daemon_write(
                    domainname_list=v,
                    rulename=k,
                    cache_object=self.repositories['upstreams-checkpoint']
                )

        static_domainname = configs.static_domainname_set
        self.set_static_list = set()
        # 获取配置文件中静态域名集

        if isinstance(static_lists := static_domainname.get('list'), list):
            # 判断配置文件中 static -> list部分使用list
            # "list" = ["/home/guocl/Python/proj002/src/etc/pydns/list/hosts_devel"]
            # or
            # "list" = "/home/guocl/Python/proj002/src/etc/pydns/list/hosts_devel"
            for static_list in static_lists:
                if ospath.exists(static_list):
                    # 处理hosts列表
                    with open(static_list, 'r') as fd_hosts:
                        for c in fd_hosts:
                            c = c.strip().lower().rstrip('\n')
                            if len(c) > 0 and not c.startswith('#'):
                                # 判断空行与注释行
                                i = tuple(c.rstrip('\n').lower().split())
                                if len(i) > 1:
                                    # 判断格式错误
                                    self.set_static_list.add(i[1].strip())
        if isinstance(static_lists := static_domainname.get('list'), str):
            # 判断配置文件中 static -> list部分使用list
            # "list" = ["/home/guocl/Python/proj002/src/etc/pydns/list/hosts_devel"]
            # or
            # "list" = "/home/guocl/Python/proj002/src/etc/pydns/list/hosts_devel"
            if ospath.exists(static_lists):
                # 处理hosts列表
                with open(static_lists, 'r') as fd_hosts:
                    for c in fd_hosts:
                        c = c.strip().lower().rstrip('\n')
                        if len(c) > 0 and not c.startswith('#'):
                            # 判断空行与注释行
                            i = tuple(c.rstrip('\n').lower().split())
                            if len(i) > 1:
                                # 判断格式错误
                                self.set_static_list.add(i[1].strip())
        if static_domainnames_v4 := static_domainname.get('domainname_v4'):
            for c in static_domainnames_v4:
                c = c.strip().lower().rstrip('\n')
                # 判断空行与注释行
                i = tuple(c.rstrip('\n').lower().split())
                self.set_static_list.add(i[0].strip())
        if static_domainnames_v6 := static_domainname.get('domainname_v6'):
            for c in static_domainnames_v6:
                c = c.strip().lower().rstrip('\n')
                # 判断空行与注释行
                i = tuple(c.rstrip('\n').lower().split())
                self.set_static_list.add(i[0].strip())

        self.daemon_write(
            domainname_list=self.set_static_list,
            rulename=self.static_rule,
            cache_object=self.repositories['upstreams-checkpoint']
        )

        logger.debug(f'set_static_list: {self.set_static_list}')

        normalpriority_dataclass.clear()
        for set_name in self.set_usage.get('domain-set').get('ip-set').keys():

            normalpriority_dataclass[set_name] = set()
            value = self.domainname_set.get(set_name).get('list')
            # 处理域名集合
            if isinstance(value, list):
                for path_with_filename in value:
                    if ospath.exists(path_with_filename):
                        with open(path_with_filename, 'r') as f:
                            tmp_list = normalpriority_dataclass.get(set_name)
                            for c in f:
                                if c.startswith('regexp:'):
                                    # 未支持正则
                                    continue
                                c = c.strip().lower().replace('full:', '', 1).rstrip('\n')
                                # 由于该域名列表来自v2ray中的txt部分，列表中有full：开头与regexp开头
                                if len(c) > 0 and not c.startswith('#'):
                                    tmp_list.add(c)
            elif isinstance(path_with_filename := value, str):
                if ospath.exists(path_with_filename):
                    with open(path_with_filename, 'r') as f:
                        tmp_list = normalpriority_dataclass.get(set_name)
                        for c in f:
                            if c.startswith('regexp:'):
                                # 未支持正则
                                continue
                            c = c.strip().lower().replace('full:', '', 1).rstrip('\n')
                            if len(c) > 0 and not c.startswith('#'):
                                tmp_list.add(c)
            value = self.domainname_set.get(set_name).get('domainname')
            if value:
                tmp_list = normalpriority_dataclass.get(set_name)
                for domainname in value:
                    tmp_list.add(domainname)

        if len(normalpriority_dataclass) > 0:
            for k, v in normalpriority_dataclass.items():
                self.daemon_write(
                    domainname_list=v,
                    rulename=k,
                    cache_object=self.repositories['ip-sets-checkpoint']
                )


        logger.debug(f'upstreams_list: {self.repositories['upstreams-checkpoint'].get('com').get('googleadservices')}')

    def daemon_write(self, domainname_list: list, rulename: str, cache_object: object):
        for i in domainname_list:
            tmp_daemon = i.split('.')
            tmp_daemon.reverse()

            def convertdict(updict, nextkey, datalist):
                if isinstance(updict, str):
                    if len(datalist) > 2:
                        one_key = cache_object.get(updict)
                        if one_key is None:
                            cache_object.update({updict: {}})
                            two_key = cache_object.get(updict)
                            two_key.update({nextkey: {}})
                            return two_key.get(nextkey)
                        else:
                            savedata = one_key.get(nextkey)
                            if savedata:
                                return savedata
                            else:
                                one_key.update({nextkey: {}})
                                two_key = one_key.get(nextkey)
                                return two_key
                    else:
                        one_key = cache_object.get(updict)
                        if one_key is None:
                            cache_object.update({updict: {}})
                            two_key = cache_object.get(updict)
                            two_key.update(
                                {nextkey: {self.default_rule: rulename}})
                            return two_key.get(nextkey)
                        else:
                            savedata = one_key.get(nextkey)
                            if savedata:
                                savedata.update(
                                    {self.default_rule: rulename})
                                return savedata
                            else:
                                one_key.update(
                                    {nextkey: {self.default_rule: rulename}})
                                two_key = one_key.get(nextkey)
                                return two_key

                elif isinstance(updict, dict):
                    if nextkey == datalist[-1]:
                        # 判断是否为最后一级域名
                        # 与
                        # 只有顶级域
                        if len(updict) == 0:
                            updict.update(
                                {nextkey: {self.default_rule: rulename}})
                        else:
                            top_key = updict.get(nextkey)
                            # 检查传入的字典缓存是否已经存在顶级域
                            if top_key:
                                top_key.update(
                                    {self.default_rule: rulename})
                            else:
                                updict[nextkey] = {self.default_rule: rulename}
                    else:
                        if len(updict) == 0:
                            updict.update({nextkey: {}})
                        else:
                            _tmp = updict.get(nextkey)
                            if _tmp:
                                return _tmp
                            else:
                                updict.update({nextkey: {}})
                                _tmp = updict.get(nextkey)
                                return _tmp
                    return updict.get(nextkey)
            reduce(lambda x, y: convertdict(x, y, tmp_daemon), tmp_daemon, cache_object)


class RULESearch(RULERepository):
    """查找域名,选择出上游DNS服务器集合名称
    """

    __instance = None

    __slots__ = (
        'searchcache',
        'customizerules',
        'upserver',
        'new_cache',
        'rulesfull',
        'static_rule',
        'ruleswildcard',
        'none_results',
        'upstream_cont',
        'rulesstatic',
        'resultlist',
        'default_rule',
        'configs',
    )

    def __new__(cls):
        if not cls.__instance:
            cls.__instance = super(RULESearch, cls).__new__(cls)
        return cls.__instance

    def __init__(self):
        super(RULESearch, self).__init__()

        self.configs = configs
        self.customizerules = {}
        # 用于自定义修改域名规则
        # 用于保存cname与qname关系
        # NOTE：如果将用户自定义rule存放与rulesfull，会因为lru算法将其删除

        self.rulesfull = LRUCache(maxsize=self.configs.lru_maxsize)
        # rulesfull: LRUCache({domain: rule1}, ...)
        # 用于存放非通配符域名规则，该字典优先于ruleswildcard

        self.rulesstatic = {}
        # 作为类似hosts，由手工设置的dns记录
        # rulesstatic: {domain: rule1, domain2: rule2,...}

        self.ruleswildcard = {}
        # ruleswildcard: 用于设置通配符域名规则，字典结构与rulestabs相同，该字典可缓存
        # 作用：使用cli命令： rules -n *.push.apple.com -r cn
        # 设置后push.apple.com下所有子域都将修改规则从proxy到cn
        # ruleswildcard: {'com': {'baidu': {'www': {'default-rule': 'cn'}, 'teiba':{'default-rule': 'cn'}}},...}

        self.searchcache = ChainMapRule(
            self.customizerules,
            self.rulesfull,
            self.ruleswildcard,
            self.rulesstatic
        )
        # todo NOTE: 计划添加关键字匹配

        self.upserver = None
        self.none_results = {}
        self.upstream_cont = 0

        self.resultlist = []
        self.default_rule = self.configs.default_rule
        # 用于所有rules缓存中的key，为减少key的碰撞冲突，这里使用在tomlconfigre.py中随机字符串
        self.static_rule = self.configs.static_rule
        # 用于所有rulesstatic静态规则缓存中的key，为减少key的碰撞冲突，这里使用在tomlconfigre.py中随机字符串
        # 获取配置文件中的所有域名集

        for i in self.set_static_list:
            if not i.endswith('.'):
                i += '.'
            self.rulesstatic.update(
                {i: self.back_search(
                    i, self.repositories['upstreams-checkpoint']
                )
                }
            )

    def __len__(self):
        return len(self.searchcache)

    def __getstate__(self):
        """用于pickle dump
        """
        logger.debug(f'pickle dump ruleswildcard: {self.ruleswildcard}')
        return {
            'self.rulestabs': self.rulesfull.copy(),
            'ruleswildcard': self.ruleswildcard,
            'customizerules': self.customizerules
        }

    def __setstate__(self, data, **kwargs):
        """用于pickle load
        """
        self.__init__()
        for k, v in data.items():
            if k == 'self.rulestabs':
                for rulescache_key, rulescache_value in v.items():
                    if rulescache_value not in configs.rulesjson:
                        # 检查缓存中rule值与配置文件中的rule名是否存在
                        # 不存在则使用默认规则
                        rulescache_value = configs.default_upstream_rule
                    self.rulesfull.add_many({rulescache_key: rulescache_value})
            elif k == 'ruleswildcard':
                # 重启后default-rule会被重置，需要更新当前新的default-rule
                def get_key(i):
                    for key, value in i.items():
                        if isinstance(value, dict):
                            get_key(value)
                        elif isinstance(value, str):
                            i.update({self.configs.default_rule: i.pop(key)})
                            break
                get_key(v)
                self.ruleswildcard.update(v)
            elif k == 'customizerules':
                self.customizerules.update(v)

    def __getattr__(self, name):
        if name == "new_cache":
            from .dnscache import new_cache
            setattr(self, 'new_cache', new_cache)
            return getattr(self, name)
        else:
            raise AttributeError(name)

    def search(self, domainname: str, *, repositorie: str) -> str:
        """
        作用：
            1. 运行时查找域名的规则
            2. 使用cli命令时查找域名规则

        search简单缓存, 可使用pickle序列化保存到文件
        缓存self.back_search(domainname) 返回结果
        搜索范围：
            重載ChainMapRule中的get方法，因此get顺序如下
            self.customizerules,
            self.rulesfull,
            self.ruleswildcard,
            self.rulesstatic

        Return:
            str: 搜索结果
        """
        domainname = domainname.strip()
        if domainname.startswith('*') or domainname.startswith('.'):
            domainname = '.'.join(domainname.strip().split('.')[1:])

        match repositorie:
            case 'upstreams-checkpoint':
                if searchresult := self.searchcache.get(domainname):
                    logger.debug(f'in search cache hit, search result: {searchresult}')
                    return searchresult
                else:
                    searchresult = self.back_search(domainname, self.repositories[repositorie])
                    logger.debug(f'{repositorie} in search cache not hit, search result: {searchresult}')
                    if searchresult:
                        self.searchcache.add_many({domainname: searchresult})
                    else:
                        self.searchcache.add_many({domainname: self.configs.default_upstream_rule})
                    return searchresult
            case 'ip-sets-checkpoint':
                if searchresult := self.back_search(domainname, self.repositories[repositorie]):
                    logger.debug(f'in search cache not hit, search result: {searchresult}')
                    self.searchcache.add_many({domainname: searchresult})
                return searchresult

    def modify(self, domainname: str, *, rule: str) -> str:
        """
        域名规则修改, 并删除对应的缓存
        """
        enter_domainname = domainname
        if rule in self.configs.rulesjson:
            if domainname.startswith('*') or domainname.startswith('.'):
                domainname = domainname.strip().rstrip('.')
                domainname = '.'.join(domainname.strip().split('.')[1:])

                logger.debug(f'delete before rulesfull is len: {len(self.rulesfull)}')
                self.__delete_rulesfull_cache(domainname.split('.'))
                logger.debug(f'modify domainname: {domainname}, rule: {rule}, ruleswildcard: {self.ruleswildcard}')

                self.daemon_write([domainname], rule, self.ruleswildcard)
                logger.debug(f'delete after rulesfull is len: {len(self.rulesfull)}, ruleswildcard len: {len(self.ruleswildcard)}')
                return (enter_domainname, self.searchcache.get(domainname))

            cacheobj = self.searchcache.get(domainname)
            if cacheobj:
                del self.searchcache[domainname]
            self.searchcache.maps[0].update({domainname: rule})
            logger.debug(f'searchcache: {self.searchcache.maps[0]}, get: {self.searchcache.get(domainname)}')

            query_name = DNSLabel(domainname)
            logger.debug(f'rule in modify cache rule: {query_name}, rule {rule}')
            query_type = self.new_cache.search_cache.keys()
            for k in query_type:
                self.new_cache.deldata(query_name, k)
            return (domainname, self.searchcache.get(domainname))

        elif rule is None:
            return (domainname, 'rule not found')

    def back_search(self, domainname: str, cache_object: object):
        logger.debug(f'search domainname: {domainname}')
        """ domainname: api.twitter.com.
        """
        dn = domainname.rstrip('.').strip().lower().split('.')
        dn.reverse()

        tmp_list = []

        def search_cache(x, y):
            if isinstance(x, str):
                startkey = cache_object.get(x, None)
                if startkey:
                    yvalue = startkey.get(y, None)
                    if yvalue:
                        tmp_list.append(yvalue.get(self.default_rule, None))
                        return yvalue
                    else:
                        tmp_list.append(yvalue)
                    return startkey
                else:
                    tmp_list.append(startkey)
            elif isinstance(x, dict):
                nextkey = x.get(y, None)
                if nextkey:
                    tmp_list.append(nextkey.get(self.default_rule, None))
                else:
                    tmp_list.append(nextkey)
                return nextkey
            else:
                tmp_list.append(x)

        reduce(search_cache, dn)

        logger.debug(f'result list: {tmp_list}')
        result = list(filter(None, tmp_list))
        if len(result) == 0:
            return None
        else:
            return result[-1]

    def delete(self, domainname: str) -> None:
        """
        方法作用：
            删除rule规则或修改rule规则时，删除域名缓存
        """
        enter_domainname = domainname
        detail = {}
        logger.debug(f'{domainname} is in the delete')
        if domainname.startswith('*') or domainname.startswith('.'):
            domainname = domainname.strip().rstrip('.')
            domainname = '.'.join(domainname.strip().split('.')[1:])

            detail.update({'befor': self.searchcache.get(enter_domainname)})
            logger.debug(f'delete before ruleswildcard is len {len(self.ruleswildcard)}, domainname in wildcard: {domainname}')
            self.__delete_rulesfull_cache(domainname.split('.'))
            self.__delete_ruleswildcard_cache(domainname.split('.'))
            logger.debug(f'delete after ruleswildcard is {len(self.ruleswildcard)}')
            detail.update({'after': self.search(enter_domainname, repositorie='upstreams-checkpoint')})
            return {enter_domainname: detail}
        else:
            cacheobj = self.searchcache.get(domainname)
            if cacheobj:
                detail.update({'befor': cacheobj})
                del self.searchcache[domainname]
                detail.update({'after': self.search(domainname, repositorie='upstreams-checkpoint')})
                query_type = self.new_cache.search_cache.keys()
                for k in query_type:
                    self.new_cache.deldata(domainname, k)
                return {domainname: detail}

    def __delete_rulesfull_cache(self, domainname: list):
        """该方法用于在修改通配符rules时，删除rulesfull中的相应所有子域rule
        *.baidu.com 删除所有baidu.com下的子域rule
        NOTE: 如何先前添加过相应的子域规则，在设置通配符后也会被一并清空

        操作对象：rulesfull
        实现：
        arg： ’*.baidu.com' -> ['com', 'baidu']
        rulesfull: ['com', 'baidu', 'www']
        算法： for循环遍历所有rulesfull将key（域名）转换为列表，与arg进行对比
        对比过程： 将对比结果True放入results列表中，子域True的数量与arg相同就视为子域
        对比前提： rulesfull中的key（域名）转换为列表后，需要比arg的长度长或相等

        Args:
            domainname (list): ['baidu', 'com']
        """
        results = []
        domainname.reverse()
        __rulesfull = self.rulesfull.copy()
        for i in __rulesfull:
            list_domainname_cache = i.split('.')[:-1]
            list_domainname_cache.reverse()
            if len(list_domainname_cache) >= len(domainname):
                for delete_domainname, cache_domainname in zip(domainname, list_domainname_cache):
                    if delete_domainname == cache_domainname:
                        results.append(True)
                    else:
                        results.append(False)
                        break

                if all(results):
                    self.rulesfull.delete(i)
                results.clear()

    def __delete_ruleswildcard_cache(self, domainname: list):
        """
        方法作用： 用于在删除通配符rules时，删除ruleswildcard中的相应域名方法
        操作对象：ruleswildcard
        变量作用：
            ruleswildcard:
            {'com': {'apple': {'push': {'ad': {'36c253f27fe20fa45bc60f58': 'cn'}, '36c253f27fe20fa45bc60f58': 'cn'}, 'www': {'36c253f27fe20fa45bc60f58': 'cn'}}}, 'baidu': {'push': {'ad': {'36c253f27fe20fa45bc60f58': 'cn'}}}}

            domainname:
            ['com', 'apple', 'push']

        Note: '36c253f27fe20fa45bc60f58' key为default_rule随机值, 每次重启服务后重新生成随机值

        结果：
            传入domainname时
                domainname = ['com', 'apple', 'push']

            befor ruleswildcard:
            {'com': {'apple': {'push': {'ad': {'36c253f27fe20fa45bc60f58': 'cn'}, '36c253f27fe20fa45bc60f58': 'cn'}, 'www': {'36c253f27fe20fa45bc60f58': 'cn'}}}, 'baidu': {'push': {'ad': {'36c253f27fe20fa45bc60f58': 'cn'}}}}
            after ruleswildcard:
            {'com': {'apple': {'push': {'36c253f27fe20fa45bc60f58': 'cn'}, 'www': {'36c253f27fe20fa45bc60f58': 'cn'}}}, 'baidu': {'push': {'ad': {'36c253f27fe20fa45bc60f58': 'cn'}}}}

        """
        def recder_decorator(function):
            """
            函数作用： 该装饰器用于删除通配符规则时的记录路径
            变量：
                updata作用： 用于记录需要删除整个字典的路径，将获取到的路径插入到列表中
                upkey作用： 用于记录需要删除整个字典的key，将获取到的路径插入到列表中

            注意：由于default_rule使用了随机值，因此不可使用configs中的default_rule
            """
            updata = []
            upkey = []
            default_rule = None

            def wrapper(*args, **kwargs):
                nonlocal updata, upkey, default_rule
                updata.insert(0, args[0])
                upkey.insert(0, args[1])
                _end, default_rule = function(
                    args[0],
                    args[1],
                    updata=updata,
                    upkey=upkey,
                    default_rule=default_rule,
                    data=args[2]
                )
                return _end
            return wrapper

        @recder_decorator
        def delete_validated(x, y, *, updata: list[dict], upkey: list[str], default_rule: str = None, data: list = None):
            """
            遍历通配符rules缓存，验证是否有可删除的数据, 并记录查找到的default_rule
            因为default_rule随机字符串，每次重启服务后变化
            如果未查询到default_rule，则不删除rules缓存操作，因为查询时如果未查询到，则会返回None
            """
            if isinstance(x, dict):
                _end = x.get(y)
                if _end:
                    if len(_end) == 1:
                        """
                        _end: 中只有一个数据
                        example: 
                            {'ad': {'36c253f27fe20fa45bc60f58': 'cn'}}
                        """
                        if len(set(data) - set(upkey)) == 0 and isinstance(*_end.values(), str):
                            """
                            判断需要删除域名列表长度与装饰器中的列表长度是否一致，以此为判断遍历结束，
                            且数据为{'ad': {'36c253f27fe20fa45bc60f58': 'cn'}}时
                            且需要删除的域名列表长度为1，就说明遍历结束，保存key,并执行删除方法
                            """
                            default_rule = [*_end.keys()][0]
                            updata.insert(0, _end)
                            upkey.insert(0, default_rule)
                            delete_vaule(real_updata=updata, real_upkey=upkey, default_rule=default_rule)
                            return _end, default_rule
                        else:
                            return _end, default_rule
                    else:
                        if len(set(data) - set(upkey)) == 0:
                            """
                            用于判断遍历是否结束
                            如果结束，但是_end中的值为：{'ad': {'36c253f27fe20fa45bc60f58': 'cn'}, '36c253f27fe20fa45bc60f58': 'cn'}
                            也就说明需要删除的通配符域名下有子域或主机单独设置了规则
                            设计思路：不删除通配符以下的主机规则，只删除通配符当前层级规则，因为主机优先，未匹配到主机才选择选择规则
                            """
                            # 判断需要遍历的数据已经完成
                            for k, v in _end.items():
                                if isinstance(v, str):
                                    default_rule = k
                            delete_vaule(real_updata=updata, real_upkey=upkey, default_rule=default_rule)
                        return _end, default_rule
                else:
                    return _end, default_rule
            else:
                return x, None

        def delete_vaule(real_updata, real_upkey, default_rule):
            """
            删除通配符规则方法
            for 循环下使用深度复制，一个用于遍历，一个真实变量用于操作修改
            """
            _upkey = deepcopy(real_upkey)
            _updata = deepcopy(real_updata)
            for key, value in zip(_upkey, _updata):
                _data = value.get(key)
                if default_rule in _data:
                    # 判断是否有默认rules
                    real_data = real_updata[_updata.index(value)]
                    if len(_data) != 1:
                        real_data[key].pop(default_rule)
                    else:
                        real_data.pop(key)
                        if len(real_data) != 0:
                            # 判断pop后是否还有数据, 如果没有数据继续循环一次将空字典pop
                            break
                else:
                    # 验证configs in _data操作后是否没有任何键值对
                    if len(real_updata[_updata.index(value)].get(key)) == 0:
                        real_updata[_updata.index(value)].pop(key)
                    continue

        domainname.reverse()
        reduce(lambda x, y: delete_validated(
            x, y, domainname), domainname, self.ruleswildcard)

    def cname_map_qname(self, rule: str, cname: str):

        if rule is None:
            rule = self.default_rule
        logger.debug(f'cname {cname} rule is {rule}')
        self.customizerules.update({str(cname): rule})

class IPRepostitory:
    """
    初始化: 参数为IP地址字符串或由IP地址字符串组成的列表

    方法：
        search() 查询IP地址是否为某个网段

    案例: 
        start_time = time.perf_counter()
        iprepostitory.search('157.148.69.74', rulename='cn')
        print(f'end time: {time.perf_counter() - start_time}')
    耗时：

        end time: 0.0001921440016303677
    """
    __slots__ = (
        'repostitorys',
        'set_usage',
        'ipverify',
        'ip_int',
        'ipset'
    )

    def __init__(self):
        self.set_usage = configs.set_usage[0]
        self.ipverify = {}
        self.ipset = configs.ipset
        self.ip_int = None
        self.repostitorys = {4: {}, 6: {}}
        normalpriority_dataclass = {}

        for set_name in self.set_usage.get('domain-set').get('ip-set').values():
            normalpriority_dataclass[set_name] = set()
            value = self.ipset.get(set_name).get('list')
            if isinstance(value, list):
                for file_name in value:
                    if ospath.exists(file_name):
                        with open(file_name, 'r') as iplists_fd:
                            for iplist in iplists_fd:
                                iplist = iplist.strip().lower().rstrip('\n')
                                if len(iplist) > 0 and not iplist.startswith('#'):
                                    tmp_ip = IP(iplist)
                                    match tmp_ip.version():
                                        case 4:
                                            repostitorys_v4 = self.repostitorys.get(4)
                                            if (repostitorys_v4_set_name := repostitorys_v4.get(set_name)) is None:
                                                repostitorys_v4.update({set_name: array('I', [])})
                                            tmp_ipint = tmp_ip.int()
                                            self.repostitorys.get(4).get(set_name).append(tmp_ipint)
                                            self.ipverify.update({tmp_ipint: tmp_ip})
                                        case 6:
                                            repostitorys_v6 = self.repostitorys.get(6)
                                            if (repostitorys_v6_set_name := repostitorys_v6.get(set_name)) is  None:
                                                repostitorys_v6.update({set_name: array('L', [])})
                                            tmp_ipint = int(tmp_ip.strHex()[2:18], 16)
                                            self.repostitorys.get(6).get(set_name).append(tmp_ipint)
                                            self.ipverify.update({tmp_ipint: tmp_ip})
            elif isinstance(value, str):
                if ospath.exists(value):
                    with open(value, 'r') as iplists_fd:
                        for iplist in iplists_fd:
                            iplist = iplist.strip().lower().rstrip('\n')
                            if len(iplist) > 0 and not iplist.startswith('#'):
                                tmp_ip = IP(iplist)
                                match tmp_ip.version():
                                    case 4:
                                        repostitorys_v4 = self.repostitorys.get(4)
                                        if (repostitorys_v4_set_name := repostitorys_v4.get(set_name)) is  None:
                                            repostitorys_v4.update({set_name: array('I', [])})
                                        tmp_ipint = tmp_ip.int()
                                        self.repostitorys.get(4).get(set_name).append(tmp_ipint)
                                        self.ipverify.update({tmp_ipint: tmp_ip})
                                    case 6:
                                        repostitorys_v6 = self.repostitorys.get(6)
                                        if (repostitorys_v6_set_name := repostitorys_v6.get(set_name)) is  None:
                                            repostitorys_v6.update({set_name: array('L', [])})
                                        tmp_ipint = int(tmp_ip.strHex()[2:18], 16)
                                        self.repostitorys.get(6).get(set_name).append(tmp_ipint)
                                        self.ipverify.update({tmp_ipint: tmp_ip})

            value = self.ipset.get(set_name).get('ip')
            if value:
                for iplist in value:
                    tmp_ip = IP(iplist)
                    match tmp_ip.version():
                        case 4:
                            repostitorys_v4 = self.repostitorys.get(4)
                            if (repostitorys_v4_set_name := repostitorys_v4.get(set_name)) is  None:
                                repostitorys_v4.update({set_name: array('I', [])})
                            tmp_ipint = tmp_ip.int()
                            self.repostitorys.get(4).get(set_name).append(tmp_ipint)
                            self.ipverify.update({tmp_ipint: tmp_ip})
                        case 6:
                            repostitorys_v6 = self.repostitorys.get(6)
                            if (repostitorys_v6_set_name := repostitorys_v6.get(set_name)) is  None:
                                repostitorys_v6.update({set_name: array('L', [])})
                            tmp_ipint = int(tmp_ip.strHex()[2:18], 16)
                            self.repostitorys.get(6).get(set_name).append(tmp_ipint)
                            self.ipverify.update({tmp_ipint: tmp_ip})

        _repostitorys = deepcopy(self.repostitorys)
        for keys, values in _repostitorys.items():
            source_values = self.repostitorys.get(keys)
            for i in values:
                source_values.update({i: memoryview(array(values.get(i).typecode, sorted(values.get(i))))})

    def search(self, ipaddr: str, *, repositorie: str) -> bool:
        ip = IP(ipaddr)
        keylist = None

        match ip.version():
            case 4:
                self.ip_int = ip.int()
                keylist = self.__binary_search(self.repostitorys.get(4).get(repositorie))
                for x in keylist:
                    if ip in self.ipverify.get(x):
                        return True
            case 6:
                self.ip_int = int(ip.strHex()[2:18], 16)
                keylist = self.__binary_search(self.repostitorys.get(6).get(repositorie))
                for x in keylist:
                    if ip in self.ipverify.get(x):
                        return True
        return False

    def __binary_search(self, keylist: memoryview):
        # 二分查找
        t_size = len(keylist) // 2
        if len(keylist) == 1:
            return keylist
        if self.ip_int >= keylist[t_size]:
            a = keylist[t_size:]
            keylist = self.__binary_search(a)
        elif self.ip_int <= keylist[t_size]:
            a = keylist[0:t_size]
            keylist = self.__binary_search(a)

        return keylist

rulesearch = None
iprepostitory = None

def module_init():
    logger.debug(f'default rule mapping to string: {configs.default_rule}')
    global rulesearch, iprepostitory

    if configs.cache_persist and ospath.exists(configs.cache_file):
        rulesearch = deserialize(RULESearch.__name__)
        if rulesearch is None:
            logger.debug('pickle data none or failed')
            rulesearch = RULESearch()
    else:
        rulesearch = RULESearch()

    iprepostitory = IPRepostitory()

if __name__ == '__main__':
    _exit(0)
