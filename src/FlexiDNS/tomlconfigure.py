
# coding: utf-8

"""
用于解析toml配置文件，以及初始化一些常量
该模块可以使用tests/tomlconfigure-test.py进行测试与调试
"""

import contextvars
from copy import deepcopy
from collections import deque
import tomllib
import tempfile
import socket
import struct
import mmap
from os import _exit, urandom, pipe, path
from multiprocessing import Pipe
from logging import DEBUG, INFO, WARNING, ERROR, CRITICAL

from IPy import IP
from dnslib import EDNSOption, QTYPE


class Share_Objects_Structure:
    # 用于服务需要使用到的共享对象, 并且无法pickle
    # 这些对象无需用户配置

    def __init__(self):

        self.FAKEIP_NAME = 'fakeip'
        self.ttl_timeout_send, self.ttl_timeout_recv = Pipe()
        self.ttl_timeout_response_recv, self.ttl_timeout_response_send = pipe()
        self.contextvars_dnsinfo = contextvars.ContextVar('dnsinfo', default=None)
        self.history = deque(maxlen=500)
        self.ipc_mmap_size: int = 4194304
        self.ipc_mmap = mmap.mmap(-1, self.ipc_mmap_size, flags=mmap.MAP_SHARED)
        self.ipc_01_mmap = mmap.mmap(-1, self.ipc_mmap_size, flags=mmap.MAP_SHARED)

        self.LOGLEVELS = {
            'debug': DEBUG,
            'info': INFO,
            'error': ERROR,
            'warning': WARNING,
            'critical': CRITICAL
            }

        self.BLACKLIST_MNAME = 'a.gtld-servers.net.'
        self.BLACKLIST_RNAME = 'nstld.verisign-grs.com'
        self.DEFAULT_RULE: urandom = urandom(12).hex()
        self.STATIC_RULE: urandom = urandom(12).hex()
        self.mmapfile: tuple = tempfile.mkstemp(prefix=f'.{__package__.lower()}_', dir='/dev/shm')
        self.LRU_MAXSIZE = 4096
        self.PIDFILE = f'/run/{__package__.lower()}.pid'
        self.SOCKFILE = f"/tmp/{__package__.lower()}.sock"

    def init(self):

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

        if configs.edns0_ipv6_address is not None:
            ipv6_address = configs.edns0_ipv6_address
            source_netmask = 64
            scope_netmask = 0
            family = 2
            source_address = socket.inet_pton(socket.AF_INET6, ipv6_address)

            edns_client_subnet_option = struct.pack(
                "!HBB16s", family, source_netmask, scope_netmask, source_address)

            self.optsv6 = [
                EDNSOption(8, edns_client_subnet_option)
            ]


class Default_Configures:
    # 定义初始值或默认值

    SERVERNAME = __package__.lower()
    CACHE_FILE =  f'/var/log/{__package__.lower()}.cache'
    CACHE_FIX = False
    CACHE_PERSIST = False

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

    BLACKLIST = {}
    DOMAINSET = {}
    STATICLIST = {}
    BLACKLIST_RCODE = "success"
    IPSET = {}
    RULESJSON = {}
    TLS_CERT = ""
    TLS_CERT_KEY = ""
    TLS_CERT_CA: str = ""
    NAMESERVER = ""
    SERVER = []


class Configures_Structure:

    def init(self, inittomlconfig):
        self.logfile = inittomlconfig.logfile
        self.logerror = inittomlconfig.logerror
        self.loglevel = inittomlconfig.loglevel
        self.logfile_size = inittomlconfig.logsize * 1024 * 1024
        self.logfile_backupcount = inittomlconfig.logcounts
        self.nameserver = inittomlconfig.nameserver
        self.dnsservers = inittomlconfig.dnsservers
        """
        dnsservers:
            {'default': [('223.5.5.5', 53, 'udp', 'edns0'), (...), (...)], 'cn': [...], 'proxy': [...]}
        """
        self.rulesjson = inittomlconfig.rulesjson
        self.bool_fakeip = inittomlconfig.bool_fakeip
        self.fakeiplist = inittomlconfig.fakeiplist
        self.fakeip_match = inittomlconfig.fakeip_match
        self.fakeip_name_servers:str = share_objects.FAKEIP_NAME
        self.fakeip_upserver = inittomlconfig.fakeip_upserver
        self.expired_reply_ttl = inittomlconfig.expired_reply_ttl
        self.ttl_max = inittomlconfig.ttl_max
        self.ttl_min = inittomlconfig.ttl_min
        self.cache_fix = inittomlconfig.cache_fix
        self.tls_cert = inittomlconfig.tls_cert
        self.tls_cert_key = inittomlconfig.tls_cert_key
        self.tls_cert_ca = inittomlconfig.tls_cert_ca
        self.fakeip_ttl = inittomlconfig.fakeip_ttl
        self.default_upstream_rule = inittomlconfig.default_upstream_rule
        self.default_upstream_server = inittomlconfig.default_upstream_server
        self.response_mode = inittomlconfig.response_mode
        self.query_threshold = inittomlconfig.query_threshold
        self.blacklist = inittomlconfig.blacklist
        self.blacklist_rcode = inittomlconfig.blacklist_rcode
        self.BLACKLIST_MNAME = inittomlconfig.BLACKLIST_MNAME
        self.BLACKLIST_RNAME = inittomlconfig.BLACKLIST_RNAME
        self.fallback = inittomlconfig.fallback
        self.ipset = inittomlconfig.ipset
        self.fallback_exclude = inittomlconfig.fallback_exclude
        self.timeout = inittomlconfig.timeout
        self.cache_persist = inittomlconfig.cache_persist
        self.cache_file = inittomlconfig.cache_file
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

        self.soa_list = set()
        if len(_soa_list := inittomlconfig.soa) > 0:
            for i in _soa_list:
                self.soa_list.add(QTYPE.__getattr__(i.upper()))

        self.set_usage = inittomlconfig._set_usage
        self.domainname_set = inittomlconfig.domainname_set_options
        self.static_domainname_set = inittomlconfig.statics
        self.basedir = inittomlconfig.basedir
        self.network_log_server = inittomlconfig.network_log_server 

        self.rulesjson.update({share_objects.DEFAULT_RULE: self.default_upstream_rule})
        """
        rulesjson:
            {
                'ad': {
                    'list': ['/path/anti-ad-domains.txt'],
                    'domainname': []
                },
                'direct': {
                    'list': ['...', ],
                    'domainname': [
                        'ipv4.icanhazip.com', '...'
                    ]
                },
                'cn': {
                    'list': ['...', ],
                    'domainname': []
                },
                'cloudflare': {
                    'list': [],
                    'domainname': []
                },
                'proxy': {
                    'list': ['...', ],
                    'domainname': []
                },
                'bdab97ef9ac7a87f5fb77789': 'default'
            }
        """


class Toml_Parse:
    # toml配置文件解析

    def __init__(self, configpath):

        self._domain_set_keys = set()

        try:
            with open(configpath, 'rb') as f:
                self.config_data = tomllib.load(f)
        except Exception as e:
            print(e)
            exit(1)
        else:
            self.gloabl_parse()
            self.edns0_parse()
            self.log_parse()
            self.tls_parse()
            self.ttl_parse()
            self.cache_parse()
            self.servers_parse()
            self.ip_set_parse()
            self.domainname_set_parse()
            self.static_parse()
            self.upstreams_parse()
            self.fakeip_parse()
            self.blacklist_parse()
            self.fallback_parse()
            self.set_usage_parse()

    def gloabl_parse(self):
        self.gloabl_options = self.config_data.get('globals', {})
        self.basedir = self.gloabl_options.get('basedir', "")
        self.nameserver = self.gloabl_options.get('nameserver', Default_Configures.SERVERNAME)
        self.response_mode = self.gloabl_options.get('response_mode', "first-response")
        self.timeout = self.gloabl_options.get('timeout', Default_Configures.TIME_OUT)
        self.query_threshold = self.gloabl_options.get('query_threshold')
        self.soa = self.gloabl_options.get('soa', Default_Configures.SOA_LIST)

    def servers_parse(self):
        self.server = []
        self.server_options = self.config_data.get('server', Default_Configures.DEFAULT_SERVER)
        for k, v in self.server_options.items():
            match k:
                case "udp":
                    _all = v.split(',')
                    for i in _all:
                        _addr_str, _port_str = i.rsplit(':', 1)
                        # todo TAG: 监听地址未作验证
                        # 后期考虑地址的大小比较，例如host使用::作为接口时，将排除其它地址接口形式
                        port = int(_port_str) if int(_port_str) else 53
                        host = _addr_str.strip("[]").strip()
                        host = '::' if host == '' else host
                        # todo TAG: udp监听冲突
                        # 使用create_datastram_connection()方法创建数据流连接时，::与0.0.0.0地址冲突
                        self.server.append({k: [host, port]})
                case "tcp":
                    _all = v.split(',')
                    for i in _all:
                        _addr_str, _port_str = i.rsplit(':', 1)
                        port = int(_port_str)
                        host = _addr_str.strip("[]").strip()
                        host = None if host == '' else host
                        self.server.append({k: [host, port]})
                case "dot":
                    if self.tls_cert is not None and self.tls_cert_key is not None:
                        _all = v.split(',')
                        for i in _all:
                            _addr_str, _port_str = i.rsplit(':', 1)
                            port = int(_port_str)
                            host = _addr_str.strip("[]").strip()
                            host = None if host == '' else host
                            self.server.append({k: [host, port]})

    def log_parse(self):
        _logs_options = self.config_data.get('logs', {
            'logfile': Default_Configures.LOG_FILE,
            'logerror': Default_Configures.LOG_ERROR,
            'loglevel': Default_Configures.LOG_LEVEL,
            'logsize': Default_Configures.LOG_SIZE,
            'logcounts': Default_Configures.LOG_COUNTS
        })
        self.logfile = _logs_options.get('logfile', Default_Configures.LOG_FILE)
        self.logerror = _logs_options.get('logerror', Default_Configures.LOG_ERROR)
        self.loglevel = _logs_options.get('loglevel', Default_Configures.LOG_LEVEL)
        self.logsize = _logs_options.get('logsize', Default_Configures.LOG_SIZE)
        self.logcounts = _logs_options.get('logcounts', Default_Configures.LOG_COUNTS)

        if self.logcounts <= 0:
            self.logcounts = Default_Configures.LOG_COUNTS

        if self.logsize <= 0:
            self.logsize = Default_Configures.LOG_SIZE

        if type(self.loglevel) == str:
            if self.loglevel.lower() not in share_objects.LOGLEVELS:
                self.loglevel = Default_Configures.LOG_LEVEL
        else:
            self.loglevel = Default_Configures.LOG_LEVEL

        network_log_server = _logs_options.get('network_log_server', None)
        if network_log_server:
            self.network_log_server = tuple(network_log_server.values())
        else:
            self.network_log_server = None

    def ttl_parse(self):
        self.ttl_max = self.gloabl_options.get('ttl_max', Default_Configures.TTL_MAX)
        self.ttl_min = self.gloabl_options.get('ttl_min', Default_Configures.TTL_MIN)
        if self.ttl_max < self.ttl_min:
            self.ttl_max = self.ttl_min
        self.fakeip_ttl = self.gloabl_options.get('fakeip_ttl', Default_Configures.TTL_FAKEIP)
        self.expired_reply_ttl = self.gloabl_options.get(
            'expired_reply_ttl',
            Default_Configures.TTL_EXPIRED_REPLY
            )
        if self.expired_reply_ttl >= self.ttl_min:
            self.expired_reply_ttl = Default_Configures.TTL_EXPIRED_REPLY

    def set_usage_parse(self):
        self._set_usage = self.config_data.get('set-usage', Default_Configures.SET_USAGE)
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

    def static_parse(self):
        self.statics = {}
        static_domainnames_v4  = {}
        static_domainnames_v6  = {}
        static_domainname_set = self.config_data.get('static', Default_Configures.STATICLIST)
        """
        static_domainname_set:
        {'list': 'hosts', 'domainname_v4': {'new.example.org': '192.168.3.3', 'cloud.example.org': '192.168.3.30', '版本控制.dns服务器': '192.168.2.32'}, 'domainname_v6': {'cloud.example.org': '2408:8248:480:31b8::1'}}
        """

        # static-set设置基于basedir join方法到完整的绝对路径
        _tmp_list = []
        if path.isabs(self.basedir) and path.exists(self.basedir):
            basedir_truster = True
        else:
            basedir_truster = False

        if isinstance(set_files := static_domainname_set.get('list'), list):
            for set_file in set_files:
                if path.isabs(set_file):
                    if path.exists(set_file):
                        _tmp_list.append(set_file)
                else:
                    if path.exists(set_file := path.join(self.basedir, set_file)) and basedir_truster:
                        _tmp_list.append(set_file)
            set_files.clear()
            set_files.extend(_tmp_list)

        elif isinstance(set_file := static_domainname_set.get('list'), str):
            if path.isabs(set_file) and path.exists(set_file):
                _tmp_list.append(set_file)
            else:
                if path.exists(set_file := path.join(self.basedir, set_file)) and basedir_truster:
                    _tmp_list.append(set_file)
                static_domainname_set.update({'list': _tmp_list})

        if __static_lists := static_domainname_set.get('list'):
            for static_list in __static_lists:
                try:
                    with open(static_list, 'r') as f:
                        for line in f:
                            new_line = line.strip().lower().rstrip('\n')
                            if len(new_line) > 0 and not new_line.startswith('#'):
                                # 判断空行与注释行
                                i = tuple(new_line.rstrip('\n').lower().split())
                                if len(i) > 1:
                                    # 判断格式错误
                                    if IP(i[0]).version() == 4:

                                        if  already_static := static_domainnames_v4.get(i[1]):
                                            already_static.append(i[0].strip())
                                        else:
                                            static_domainnames_v4.update({i[1].strip() : [i[0].strip()]})
                                    if IP(i[0]).version() == 6:

                                        if  already_static := static_domainnames_v6.get(i[1]):
                                            already_static.append(i[0].strip())
                                        else:
                                            static_domainnames_v6.update({i[1].strip() : [i[0].strip()]})
                except Exception as e:
                    continue

        if __static_domainnames_v4 := static_domainname_set.get('domainname_v4'):
            for static_name, static_rcode in __static_domainnames_v4.items():
                if already_static := static_domainnames_v4.get(static_name):
                    already_static.append(static_rcode)
                else:
                    static_domainnames_v4.update({static_name: [static_rcode]})
        if __static_domainnames_v6 := static_domainname_set.get('domainname_v6'):
            for static_name, static_rcode in __static_domainnames_v6.items():
                if already_static := static_domainnames_v6.get(static_name):
                    already_static.append(static_rcode)
                else:
                    static_domainnames_v6.update({static_name: [static_rcode]})

        if len(static_domainnames_v4) > 0:
            self.statics.update({4:static_domainnames_v4})
        if len(static_domainnames_v6) > 0:
            self.statics.update({6:static_domainnames_v6})

    def edns0_parse(self):
        # todo TAG: ipv4与ipv6
        if _edns0 := self.config_data.get('edns0'):
            self.edns0_ipv4_address = _edns0.get('ipv4_address')
            self.edns0_ipv6_address = _edns0.get('ipv6_address')
        else:
            self.edns0_ipv4_address = None
            self.edns0_ipv6_address = None

    def domainname_set_parse(self):
        self.domainname_set_options = self.config_data.get('domain-set', Default_Configures.DOMAINSET)
        self.rulesjson = self.domainname_set_options

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

    def ip_set_parse(self):
        self.ipset = {}
        self.ip_set_options = self.config_data.get('ip-set', Default_Configures.IPSET)
        _ip_set_options = self.config_data.get('ip-set', Default_Configures.IPSET)

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

    def cache_parse(self):
        self.cache_fix = self.gloabl_options.get('cachefix', Default_Configures.CACHE_FIX)
        self.cache_persist = self.gloabl_options.get('cache_persist', Default_Configures.CACHE_FIX)
        self.cache_file = self.gloabl_options.get('cache_file', Default_Configures.CACHE_FILE)

    def tls_parse(self):
        self.tls_cert = self.gloabl_options.get('tls_cert')
        self.tls_cert_key = self.gloabl_options.get('tls_cert_key')
        self.tls_cert_ca = self.gloabl_options.get('tls_cert_ca')

    def fakeip_parse(self):
        self.fakednsserver = {}
        self.fakeip_match = None
        self.bool_fakeip = False
        self.fakeip_upserver = None
        self.fakeiplist = []

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

    def fallback_parse(self):
        self.fallback = {}
        _fallback_options = self.config_data.get('fallback', {})
        self.fallback_exclude = set()
        for k, v in _fallback_options.items():
            if v.get('exclude'):
                self.fallback_exclude = set(v.get('exclude').split(','))
        for i in self.rulesjson.keys():
            self._domain_set_keys.add(i)

    def upstreams_parse(self):
        self.dnsservers = {}
        self.selectlist = {}
        __fakeip_domain_set = set()
        _upstreams_options = self.config_data.get('upstreams', Default_Configures.DEFAULT_UPSTREAMS)
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

                if share_objects.FAKEIP_NAME in k:
                    self.bool_fakeip = True
                    __fakeip_domain_set.add(i.get('domain-set'))
                    _fakeip = i.get(share_objects.FAKEIP_NAME)
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

        for k, v in self.dnsservers.items(): # 获取默认上游, dnsserver中i第一个列表作为默认
            self.default_upstream_server = v
            self.default_upstream_rule = k
            if self.default_upstream_rule is not None and self.default_upstream_server is not None:
                break

    def blacklist_parse(self):
        self.blacklist = set()
        _blacklist_options = self.config_data.get('blacklist', Default_Configures.BLACKLIST)
        _black_set = set()
        _black_list = _blacklist_options.get('domain-set', [])
        self.blacklist_rcode = _blacklist_options.get('rcode', Default_Configures.BLACKLIST_RCODE)
        self.BLACKLIST_MNAME = share_objects.BLACKLIST_MNAME
        self.BLACKLIST_RNAME = share_objects.BLACKLIST_RNAME

        if len(_black_list) > 0:
            for v in _black_list:
                _black_set.add(v)
        self.blacklist = _black_set & self._domain_set_keys

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
    inittomlconfig = Toml_Parse(configpath=configpath)
    configs.init(inittomlconfig)
    share_objects.init()

if __name__ == '__main__':
    _exit(0)
