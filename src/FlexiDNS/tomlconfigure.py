
# coding: utf-8

"""
用于解析toml配置文件，以及初始化一些常量
该模块可以使用tests/tomlconfigure-test.py进行测试与调试
"""

import contextvars
from copy import deepcopy
import tomllib
import socket
import struct
import mmap
from dataclasses import dataclass, field
from os import _exit, urandom, pipe, path
from multiprocessing import Pipe, Event

from IPy import IP
from dnslib import EDNS0, EDNSOption, QTYPE


@dataclass(order=False)
class Share_Objects_Structure:
    # 由于configs需要pickle，当无法pickle对象可放置在该对象中
    ttl_timeout_send: Pipe
    ttl_timeout_recv: Pipe
    ttl_timeout_response_recv: pipe
    ttl_timeout_response_send: pipe
    contextvars_dnsinfo: contextvars.ContextVar

    def __init__(self):
        self.ttl_timeout_send, self.ttl_timeout_recv = Pipe()
        self.ttl_timeout_response_recv, self.ttl_timeout_response_send = pipe()
        self.contextvars_dnsinfo = contextvars.ContextVar(
            'dnsinfo', default=None)

    def init(self):
        """
        ECS Select;
        OPTION_CODE:
            10 -> COOKIE
            8 -> CLIENT-SUBNET
            12 -> PADDING
        """

        OPT_NAME = None
        OPT_TYPE = 41
        OPT_UDP_LEN = 1232  # 1232建议值，http://www.dnsflagday.net/2020/index-zh-CN.html
        OPT_VERSION = 0

        if configs.edns0_ipv4_address is not None:
            ipv4_address = configs.edns0_ipv4_address
            source_netmask = 24
            scope_netmask = 0
            family = 1
            source_address = socket.inet_pton(socket.AF_INET, ipv4_address)

            edns_client_subnet_option = struct.pack(
                '!HBB4s', family, source_netmask, scope_netmask, source_address)

            self.optsv4 = [
                EDNSOption(8, edns_client_subnet_option)
            ]

            self.OPTv4 = [
                EDNS0(
                    rname=OPT_NAME,
                    rtype=OPT_TYPE,
                    udp_len=OPT_UDP_LEN,
                    version=OPT_VERSION,
                    opts=self.optsv4
                )
            ]
        else:
            self.OPTv4 = []

        if configs.edns0_ipv6_address is not None:
            ipv6_address = configs.edns0_ipv6_address
            source_netmask = 60
            scope_netmask = 0
            family = 2
            source_address = socket.inet_pton(socket.AF_INET6, ipv6_address)

            edns_client_subnet_option = struct.pack(
                "!HBB16s", family, source_netmask, scope_netmask, source_address)

            self.optsv6 = [
                EDNSOption(8, edns_client_subnet_option)
            ]

            self.OPTv6 = [
                EDNS0(
                    rname=OPT_NAME,
                    rtype=OPT_TYPE,
                    udp_len=OPT_UDP_LEN,
                    version=OPT_VERSION,
                    opts=self.optsv6
                )
            ]
        else:
            self.OPTv6 = []

        self.ipc_mmap_size: int = 4194304
        self.ipc_mmap = mmap.mmap(-1, self.ipc_mmap_size, flags=mmap.MAP_SHARED)
        self.ipc_01_mmap = mmap.mmap(-1, self.ipc_mmap_size, flags=mmap.MAP_SHARED)


@dataclass(order=False)
class Configures_Structure:

    # 定义初始值或默认值
    pidfile = f'/run/{__package__.lower()}.pid'
    blacklist: list = field(default_factory=lambda: [])
    blacklist_rcode: str = "success"
    default_rule: urandom = urandom(12).hex()
    default_server: dict = field(default_factory=lambda: {"udp": "[::1]:53"})
    ipset: dict = field(default_factory=lambda: {})
    mmapfile: str = f"/dev/shm/{__package__.lower()}.mmap"
    rulesjson: dict = field(default_factory=lambda: {})
    lru_maxsize: int = 4096
    tls_cert: str = ""
    tls_cert_key: str = ""
    tls_cert_ca: str = ""
    nameserver: str = ""
    static_rule: urandom = urandom(12).hex()
    sockfile: str = f"/tmp/{__package__.lower()}.sock"
    server: list = field(default_factory=lambda: [])
    soa_list: set = field(default_factory=lambda: {
        QTYPE.__getattr__('ptr'.upper()), })

    def init(self, inittomlconfig):
        self.logfile = inittomlconfig.logfile
        self.logerror = inittomlconfig.logerror
        self.loglevel = inittomlconfig.loglevel
        self.logfile_size = inittomlconfig.logsize * 1024 * 1024
        self.logfile_backupcount = inittomlconfig.logcounts
        self.nameserver = inittomlconfig.nameserver
        self.dnsservers = inittomlconfig.dnsservers
        self.rulesjson = inittomlconfig.rulesjson
        self.bool_fakeip = inittomlconfig.bool_fakeip
        self.fakeiplist = inittomlconfig.fakeiplist
        self.fakeip_match = inittomlconfig.fakeip_match
        self.fakeip_name_servers = inittomlconfig.fakeip_name
        self.fakeip_upserver = inittomlconfig.fakeip_upserver
        self.expired_reply_ttl = inittomlconfig.expired_reply_ttl
        self.ttl_max = inittomlconfig.ttl_max
        self.ttl_min = inittomlconfig.ttl_min
        self.tls_cert = inittomlconfig.tls_cert
        self.tls_cert_key = inittomlconfig.tls_cert_key
        self.tls_cert_ca = inittomlconfig.tls_cert_ca
        self.fakeip_ttl = inittomlconfig.fakeip_ttl
        self.default_upstream_rule = inittomlconfig.default_upstream_rule
        self.default_upstream_server = inittomlconfig.default_upstream_server
        self.response_mode = inittomlconfig.response_mode
        self.speedtcpport = inittomlconfig.speedtcpport
        self.query_threshold = inittomlconfig.query_threshold
        self.blacklist = inittomlconfig.blacklist
        self.blacklist_rcode = inittomlconfig.blacklist_rcode
        self.fallback = inittomlconfig.fallback
        self.ipset = inittomlconfig.ipset
        self.bind = inittomlconfig.bind
        self.fallback_exclude = inittomlconfig.fallback_exclude
        self.timeout = inittomlconfig.timeout
        self.query_qtypes = [
            QTYPE.HTTPS,
            QTYPE.NS,
            QTYPE.SOA,
            QTYPE.PTR,
            QTYPE.SRV,
            QTYPE.TXT
        ]
        self.cache_persist = inittomlconfig.cache_persist
        self.cache_file = inittomlconfig.cache_file
        self.max_threads = inittomlconfig.max_threads  # 记得没用这个参数了
        self.server = inittomlconfig.server
        self.edns0_ipv4_address = inittomlconfig.edns0_ipv4_address
        self.edns0_ipv6_address = inittomlconfig.edns0_ipv6_address

        if self.edns0_ipv4_address is None:
            _dnsservers = self.dnsservers.copy()
            for upstream_name, servers in _dnsservers.items():
                _tmp_list = []
                for server in servers:
                    if IP(server[0]).version() == 4:
                        _tmp_list.append((server[0], server[1], server[2], None))
                    else:
                        _tmp_list.append(server)
                self.dnsservers.update({upstream_name: _tmp_list})

        if self.edns0_ipv6_address is None:
            _dnsservers = self.dnsservers.copy()
            for upstream_name, servers in _dnsservers.items():
                _tmp_list = []
                for server in servers:
                    if IP(server[0]).version() == 6:
                        _tmp_list.append((server[0], server[1], server[2], None))
                    else:
                        _tmp_list.append(server)
                self.dnsservers.update({upstream_name: _tmp_list})

        if len(_soa_list := inittomlconfig.soa) > 0:
            for i in _soa_list:
                self.soa_list.add(QTYPE.__getattr__(i.upper()))

        self.set_usage = inittomlconfig._set_usage
        self.domainname_set = inittomlconfig.domainname_set_options
        self.static_domainname_set = inittomlconfig.static_domainname_set
        self.basedir = inittomlconfig.basedir
        self.network_log_server = inittomlconfig.network_log_server 


class TomlConfigures:
    CACHE_FILE =  f'/var/log/{__package__.lower()}.cache'
    TIME_OUT = 3.0
    SOA_LIST = ['ptr']

    LOG_FILE = f'/var/log/{__package__.lower()}.log'
    LOG_ERROR = f'/var/log/{__package__.lower()}_err.log'
    LOG_LEVEL = 'debug'
    LOG_SIZE = 1
    LOG_COUNTS = 3
    
    TTL_MAX = 7200
    TTL_MIN = 600
    TTL_FAKEIP = 6
    TTL_EXPIRED_REPLY = 1

    DEFAULT_SERVER = {'udp': ':53'}

    DEFAULT_UPSTREAMS = {
        'default': [
            {
                'protocol': 'udp',
                'address': '223.5.5.5',
                'port': 53,
                'ext': None
            }
        ]
    }

    SET_USAGE = [
        {
            'domain-set': {
                'ip-set': {},
                'upstreams': {},
                'blacklist': {}
            }
        },
    ]

    def __init__(self, configpath):


        self.fakeip_name = 'fakeip'
        with open(configpath, 'rb') as f:
            config_data = tomllib.load(f)

        _gloabls_options = config_data.get('globals', {})
        _server_options = config_data.get('server', TomlConfigures.DEFAULT_SERVER)

        _logs_options = config_data.get('logs', {
            'logfile': TomlConfigures.LOG_FILE,
            'logerror': TomlConfigures.LOG_ERROR,
            'loglevel': TomlConfigures.LOG_LEVEL,
            'logsize': TomlConfigures.LOG_SIZE,
            'logcounts': TomlConfigures.LOG_COUNTS
        })

        _fallback_options = config_data.get('fallback', {})
        _blacklist_options = config_data.get('blacklist', {'domain-set': []})
        _upstreams_options = config_data.get('upstreams', TomlConfigures.DEFAULT_UPSTREAMS)
        _domain_set_options = config_data.get('domain-set', {})
        _ip_set_options = config_data.get('ip-set', {})
        _edns0 = config_data.get('edns0')

        self._set_usage = config_data.get('set-usage', TomlConfigures.SET_USAGE)

        self.static_domainname_set = config_data.get('static', {})
        self.domainname_set_options = config_data.get('domain-set', {})
        self.basedir = _gloabls_options.get('basedir', "")

        _fakeip_domain_set = set()
        _domain_set_keys = set()

        self.dnsservers = {}
        self.rulesjson = {}
        self.ipset = {}
        self.fakednsserver = {}
        self.selectlist = {}
        self.blacklist = set()
        self.speedtcpport = 'tcp'
        self.fakeip_match = None
        self.max_threads = 3
        self.bool_fakeip = False
        self.fakeip_upserver = None

        self.nameserver = _gloabls_options.get('nameserver')
        self.expired_reply_ttl = _gloabls_options.get('expired_reply_ttl', TomlConfigures.TTL_EXPIRED_REPLY)
        self.ttl_max = _gloabls_options.get('ttl_max', TomlConfigures.TTL_MAX)
        self.ttl_min = _gloabls_options.get('ttl_min', TomlConfigures.TTL_MIN)
        self.fakeip_ttl = _gloabls_options.get('fakeip_ttl', TomlConfigures.TTL_FAKEIP)
        self.response_mode = _gloabls_options.get('response_mode', "first-response")
        self.timeout = _gloabls_options.get('timeout', TomlConfigures.TIME_OUT)
        self.query_threshold = _gloabls_options.get('query_threshold')
        self.soa = _gloabls_options.get('soa', TomlConfigures.SOA_LIST)
        self.cache_persist = _gloabls_options.get('cache_persist', False)
        self.cache_file = _gloabls_options.get('cache_file', TomlConfigures.CACHE_FILE)
        self.tls_cert = _gloabls_options.get('tls_cert')
        self.tls_cert_key = _gloabls_options.get('tls_cert_key')
        self.tls_cert_ca = _gloabls_options.get('tls_cert_ca')

        self.logfile = _logs_options.get('logfile', TomlConfigures.LOG_FILE)
        self.logerror = _logs_options.get('logerror', TomlConfigures.LOG_ERROR)
        self.loglevel = _logs_options.get('loglevel', TomlConfigures.LOG_LEVEL)
        self.logsize = _logs_options.get('logsize', TomlConfigures.LOG_SIZE)
        self.logcounts = _logs_options.get('logcounts', TomlConfigures.LOG_COUNTS)

        network_log_server = _logs_options.get('network_log_server', None)
        if network_log_server:
            self.network_log_server = tuple(network_log_server.values())
        else:
            self.network_log_server = None

        if _edns0:
            self.edns0_ipv4_address = _edns0.get('ipv4_address')
            self.edns0_ipv6_address = _edns0.get('ipv6_address')
        else:
            self.edns0_ipv4_address = None
            self.edns0_ipv6_address = None

        # self.speedtcpport = self.cfg.getint('speed check', 'tcp')
        self.bind = []
        self.fakeiplist = []
        self.fallback = {}

        self.rulesjson = _domain_set_options

        self.fallback_exclude = set()
        for k, v in _fallback_options.items():
            if v.get('exclude'):
                self.fallback_exclude = set(v.get('exclude').split(','))
        for i in self.rulesjson.keys():
            _domain_set_keys.add(i)
        """
        self.dnsservers: 
        before
            {'default': [{'protocol': 'udp', 'address': '119.29.29.29', 'port': 53, 'domain-set': ''}, {'protocol': 'udp', 'address': '223.5.5.5', 'port': 53, 'domain-set': ''}], 'cn': [{'protocol': 'udp', 'address': '119.29.29.29', 'port': 53, 'domain-set': 'cn'}, {'protocol': 'udp', 'address': '223.5.5.5', 'port': 53, 'domain-set': 'cn'}], 'gfw': [{'protocol': 'udp', 'address': '119.29.29.29', 'port': 53, 'domain-set': 'proxy'}], 'fakeip': [{'protocol': 'udp', 'address': '223.5.5.5', 'port': 15656, 'fakeip': '198.18.0.0/15', 'fakeip6': 'fc00::/64', 'domain-set': 'proxy'}]}
        after
            {'default': [('119.29.29.29', 53), ('223.5.5.5', 53)], 'cn': [('119.29.29.29', 53), ('223.5.5.5', 53)], 'proxy': [('223.5.5.5', 53)], 'fakeip': [('fd11:88::1', 15656)]}
        """

        _szie = []
        for k, v in _upstreams_options.items():
            _szie.append(len(v))
            self.dnsservers.update({k: []})
            for i in v:
                address = i.get('address')
                if not socket.has_dualstack_ipv6():
                    if IP(address).version() == 6:
                        continue
                port = i.get('port')
                protocol = i.get('protocol')
                ext = i.get('ext')
                # todo TAG: 缺少协议字符串验证，可使用set()集合验证
                checkresults = all(list(map(self.check_ip, {address})))
                if checkresults:
                    self.dnsservers[k].append((address, port, protocol, ext))
                else:
                    print(f'Invalid upstream dns server ip address {address}')
                    continue

                if self.fakeip_name in k:
                    self.bool_fakeip = True
                    _fakeip_domain_set.add(i.get('domain-set'))
                    _fakeip = i.get(self.fakeip_name)
                    if _fakeip:
                        checkresults = all(
                            list(map(self.check_ip, _fakeip.split(','))))
                        if checkresults:
                            self.fakeiplist = _fakeip.split(',')
                        else:
                            self.bool_fakeip = False

        _dnsservers = self.dnsservers.copy()
        for k, v in _dnsservers.items():
            if len(v) == 0:
                self.dnsservers.pop(k)

        for k, v in self.dnsservers.items():
            for i in v:
                if 'fakeip' in i:
                    self.bool_fakeip = True
                    self.fakeip_match = k
                    self.fakeip_upserver = i
                else:
                    self.bool_fakeip = False
                    self.fakeip_match = None
                    self.fakeip_upserver = None

        for k, v in self.dnsservers.items(): # 获取默认上游, dnsserver中i第一个列表作为默认
            self.default_upstream_server = v
            self.default_upstream_rule = k
            if self.default_upstream_rule is not None and self.default_upstream_server is not None:
                break

        _tmp_rule_miss = set()

        for i in _domain_set_keys:
            if i not in self.dnsservers.keys():
                _tmp_rule_miss.add(i)

        _black_set = set()
        _black_list = _blacklist_options.get('domain-set', [])
        self.blacklist_rcode = _blacklist_options.get('rcode', None)

        if len(_black_list) > 0:
            for v in _black_list:
                _black_set.add(v)
        self.blacklist = _black_set & _domain_set_keys

        self.fallback = _fallback_options

        self._server = _server_options
        self.server = []
        for k, v in _server_options.items():
            match k:
                case "udp":
                    _all = v.split(',')
                    for i in _all:
                        _addr_str, _port_str = i.rsplit(':', 1)
                        # todo TAG: 监听地址未作验证
                        # 后期考虑地址的大小比较，例如host使用::作为接口时，将排除其它地址接口形式
                        self.port = int(_port_str) if int(_port_str) else 53
                        self.host = _addr_str.strip("[]").strip()
                        self.host = '::' if self.host == '' else self.host
                        # todo TAG: udp监听冲突
                        # 使用create_datastram_connection()方法创建数据流连接时，::与0.0.0.0地址冲突
                        self.server.append({k: [self.host, self.port]})
                case "tcp":
                    _all = v.split(',')
                    for i in _all:
                        _addr_str, _port_str = i.rsplit(':', 1)
                        self.port = int(_port_str)
                        self.host = _addr_str.strip("[]").strip()
                        self.host = None if self.host == '' else self.host
                        self.server.append({k: [self.host, self.port]})
                case "dot":
                    if self.tls_cert is not None and self.tls_cert_key is not None:
                        _all = v.split(',')
                        for i in _all:
                            _addr_str, _port_str = i.rsplit(':', 1)
                            self.port = int(_port_str)
                            self.host = _addr_str.strip("[]").strip()
                            self.host = None if self.host == '' else self.host
                            self.server.append({k: [self.host, self.port]})

        # domain-set设置基于basedir join方法到完整的绝对路径
        for _set_lists in self.domainname_set_options.values():
            file_lists = _set_lists.get('list')
            if isinstance(file_lists, list):
                _tmp_list = []
                for set_file in file_lists:
                    if set_file.startswith('/'):
                        _tmp_list.append(set_file)
                        continue
                    _tmp_list.append(path.join(self.basedir, set_file))
                file_lists.clear()
                file_lists.extend(_tmp_list)
            elif isinstance(file_lists, str):
                _set_lists.update(
                    {'list': path.join(self.basedir, file_lists)})

        # static-set设置基于basedir join方法到完整的绝对路径
        for _set_lists in self.static_domainname_set:
            if isinstance(set_files := self.static_domainname_set[_set_lists], list):
                _tmp_list = []
                for set_file in set_files:
                    if set_file.startswith('/'):
                        _tmp_list.append(set_file)
                        continue
                    _tmp_list.append(path.join(self.basedir, set_file))
                set_files.clear()
                set_files.extend(_tmp_list)
            elif isinstance(set_file := self.static_domainname_set[_set_lists], str):
                if set_file.startswith('/'):
                    _tmp_list.append(set_file)
                    continue
                self.static_domainname_set.update(
                    {_set_lists: path.join(self.basedir, set_file)})

        # ip-set字段设置基于basedir join方法到完整的绝对路径
        for _set_value in _ip_set_options.values():
            lists = _set_value.get('list')
            if isinstance(lists, list):
                _tmp_list = []
                for set_file in lists:
                    if set_file.startswith('/'):
                        _tmp_list.append(set_file)
                        continue
                    else:
                        _tmp_list.append(path.join(self.basedir, set_file))
                lists.clear()
                lists += _tmp_list
            elif isinstance(lists, str):
                _set_value.update({'list': path.join(self.basedir, lists)})
        self.ipset = _ip_set_options

        # 验证set-usage值在ip-set中是否存在相应的IP列表集合
        _set_usage  = deepcopy(self._set_usage[0])
        for ipset_name in _set_usage.get('domain-set').get('ip-set'):
            ipset_value = self.ipset.get(ipset_name)
            if ipset_value is None:
                self._set_usage[0].get('domain-set').get('ip-set').pop(ipset_name)

        # 验证set-usage值在domainname-set中是否存在相应的域名列表集合
        _set_usage  = deepcopy(self._set_usage[0])
        for ipset_name in _set_usage.get('domain-set').get('ip-set'):
            ipset_value = self.domainname_set_options.get(ipset_name)
            if ipset_value is None:
                self._set_usage[0].get('domain-set').get('ip-set').pop(ipset_name)

        # 验证set-usage值在domainname-set中是否存在相应的域名列表集合
        _set_usage  = deepcopy(self._set_usage[0])
        for domainnameset_name in _set_usage.get('domain-set').get('upstreams'):
            domainnameset_value = self.domainname_set_options.get(domainnameset_name)
            if domainnameset_value is None:
                self._set_usage[0].get('domain-set').get('upstreams').pop(domainnameset_name)

        # 验证set-usage值在ad-set中是否存在相应的域名列表集合
        _set_usage  = deepcopy(self._set_usage[0])
        for blacklistset_name in _set_usage.get('domain-set').get('blacklist'):
            blacklistset_value = self.domainname_set_options.get(blacklistset_name)
            if blacklistset_value is None:
                self._set_usage[0].get('domain-set').get('blacklist').pop(blacklistset_name)

    def check_ip(self, ip):
        try:
            IP(ip)
        except ValueError:
            return False
        else:
            return True


configs = Configures_Structure()
share_objects = Share_Objects_Structure()


def loader_config(configpath):
    inittomlconfig = TomlConfigures(configpath=configpath)
    configs.init(inittomlconfig)
    share_objects.init()


if __name__ == '__main__':
    _exit(0)
