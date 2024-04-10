
# coding: utf-8

import asyncio
import copy
import time
import pickle
import os
import socket
import struct

from .dnsclient import query_create_tasklist
from random import shuffle
from itertools import zip_longest
from logging import getLogger

from dnslib import RCODE, EDNSOption, QTYPE, DNSRecord, QR, SOA, RR, CNAME, DNSError, DNSBuffer, DNSQuestion, DNSHeader, BimapError, EDNS0

from .dnstoml import configs, share_objects
from .dnscache import new_cache
from .dnsrules_new import rulesearch, iprepostitory
from .dnslog import dnsidAdapter

logger = getLogger(__name__)
contextvars_dnsinfo = share_objects.contextvars_dnsinfo
logger = dnsidAdapter(logger, {'dnsinfo': contextvars_dnsinfo})


class Dnspkg(DNSRecord):

    def __init__(self, header, questions, rr=None, auth=None, ar=None, rule=None):
        self.ipc_mmap = share_objects.ipc
        self.configs = configs
        self.sock = None
        self.edns0 = []

        self.header = header
        self.response_header = None
        self.questions = questions
        self.rr = rr or []
        self.auth = auth or []
        self._ar = ar or []
        self.ar = []
        self.code_state = [ True, True ] # [ code8, code10 ]
        self.cookie = None
        self.rule = rule

        contextvars_dnsinfo.set(
            {
                'address': self.client,
                'id': self.header.id,
                'qname': self.q.qname,
                'qtype': self.q.qtype
            }
        )
        # 上下文变量不可放在实例属性上方，因为这些属性还未初始化完成

    def __setstate__(self, state):
        self.new_cache = new_cache
        self.rulesearch = rulesearch
        self.rules = state['rules']
        self.configs = state['configs']
        self.upserver = state['upserver']
        self.sock = None
        self.client = state['client']
        self.cachedata = None
        self.header = state['header']
        self.response_header = None
        self.questions = state['questions']
        self.rr = state['rr']
        self.auth = state['auth']
        self.ar = state['ar']
        self._ar = state['_ar']
        self.code_state = state['code_state']
        self.cookie = state['cookie']

    def check_edns_cookie(self):
        pass

    def _edns0(self):
        """
        数据字段：Additional（附加资源记录）
        作用：判断客户端是否自带cookie，如果没有，则添加
        [
            <DNS OPT: edns_ver=0 do=0 ext_rcode=0 udp_len=1232>
                <EDNS Option: Code=10 Data='f592d4eadcce3b23'>
                <EDNS Option: Code=8 Data='0001201164fad64c'>
        ]
        """
        self.ar = copy.deepcopy(self._ar)

        for ar in self.ar:
            for opts in ar.rdata:
                if opts.code == 10:
                    self.code_state[1] = False
                elif opts.code == 8:
                    self.code_state[0] = False

        if self.code_state[1]:
            self.add_ar(self.OPTCOOKIE)

        if self.code_state[0]:
            if self.q.qtype == QTYPE.A:
                for ar in self.ar:
                    ar.rdata.extend(self.OPTv4)
                    self.code_state[0] = False
            elif self.q.qtype == QTYPE.AAAA:
                for ar in self.ar:
                    ar.rdata.extend(self.OPTv6)
                    self.code_state[0] = False

        logger.debug(f'edns0: {self.ar}')
        bytes_dnspkg = self.pack()
        self.ar.clear()
        return bytes_dnspkg

    def __getstate__(self):
        return {
            'configs': self.configs,
            'upserver': self.upserver,
            'rules': self.rules,
            'client': self.client,
            'header': self.header,
            'questions': self.questions,
            'rr': self.rr,
            'auth': self.auth,
            'ar': self.ar,
            '_ar': self._ar,
            'code_state': self.code_state,
            'cookie': self.cookie
        }

    def __str__(self) -> str:
        return f'{self.__class__.__name__}({self.rules, self.rr, self.ar, self.auth, self.header})'

    def __getattr__(self, name):
        # 延迟初始化实例属性
        match name:
            case 'OPTv4':
                setattr(self, 'OPTv4', copy.deepcopy(share_objects.optsv4))
                return getattr(self, name)
            case 'OPTv6':
                setattr(self, 'OPTv6', copy.deepcopy(share_objects.optsv6))
                return getattr(self, name)
            case 'OPTCOOKIE':
                """
                ECS Select;
                    OPTION_CODE:
                        10 -> COOKIE
                        8 -> CLIENT-SUBNET
                        12 -> PADDING

                    OPT_NAME = None
                    OPT_TYPE = 41
                    OPT_UDP_LEN = 1232  建议值，http://www.dnsflagday.net/2020/index-zh-CN.html
                    OPT_VERSION = 0
                """
                cookie = os.urandom(8) if self.cookie is None else self.cookie
                setattr(self, 'OPTCOOKIE', EDNS0(
                    udp_len=1232,
                    version=0,
                    opts=[EDNSOption(10, cookie)]
                    )
                )
                return getattr(self, name)
            case 'ipset_rule':
                # 当请求域名无缓存时，也就是第一次请求解析时，在none_cache_method方法中调用该属性
                setattr(self, 'ipset_rule', self.rulesearch.search(str(self.q.qname), repositorie='ip-sets-checkpoint'))
                return getattr(self, name)

    async def response_dns_package(self):
        if (sock := self.sock) is not None:
            client = self.client
            self.ar.clear()
            self.ar.extend(self._ar)
            logger.debug(f'dnspkg ar {self.ar}')
            data = self.pack()
            match sock.get_extra_info('socket').type:
                case socket.SOCK_STREAM:
                    data_length = len(data)
                    tcpdata = struct.pack('!H', data_length) + data
                    try:
                        sock.write(tcpdata)
                    except AttributeError as error:
                        logger.error(f'attribute error: {error}')
                    finally:
                        sock.close()
                case socket.SOCK_DGRAM:
                    sock.sendto(data, client)
                case _:
                    logger.error(
                        f"response_dns_package sock is None client: {client}, data: {data}")
            logger.debug(f"response data time")
        else:
            logger.error(
                f'socket is None client: {self.client}, dnspkg: {self.q.qname}, sock {self.sock}')

    def update_cache(self):
        """
        1:用于更新ttl超时的缓存数据
        2:用于上游查询后返回更新缓存数据
        """

        if self.response_header:
            # response_header有数据时，为本实例向上游服务器请求返回
            self.header.set_rcode(self.response_header.get_rcode())
        else:
            # response_header没有数据时，为dnsttlout进程请求后返回
            self.response_header = self.header

        rrttl = 0
        min_ttl = self.configs.ttl_min
        max_ttl = self.configs.ttl_max

        for rr, auth in zip_longest(self.rr, self.auth, fillvalue=None):

            if rr:
                if rr.rtype == QTYPE.CNAME:
                    self.rulesearch.cname_map_qname(cname=rr.rdata, rule=self.rule)
                    logger.debug(f'qname: {self.q.qname}, cname: {rr.rdata}')
                    self.new_cache.set_cnamemap(self.q.qname, rr.rdata)

                logger.debug(f'original rr ttl: {rr.ttl}')
                if rr.ttl <= min_ttl:
                    rrttl = min_ttl
                    rr.ttl = rrttl
                elif rr.ttl >= max_ttl:
                    rrttl = max_ttl
                    rr.ttl = rrttl
                else:
                    rrttl = rr.ttl

            if auth:
                logger.debug(f'original auth ttl: {auth.ttl}')
                if auth.ttl <= min_ttl:
                    rrttl = min_ttl
                    auth.ttl = rrttl
                elif auth.ttl >= max_ttl:
                    rrttl = max_ttl
                    auth.ttl = rrttl
                else:
                    rrttl = auth.ttl

        self.new_cache.setttl(self.q.qname, self.q.qtype, rrttl)
        self.new_cache.setdata(self)

        if len(self.rr) == 0 and len(self.auth) == 0:
            self.new_cache.deldata(self.q.qname, self.q.qtype)
            # 上游服务器响应内容为空时，将rcode设置为nxdomain
            self.header.set_rcode(RCODE.NXDOMAIN)

    def pack(self):
        return super().pack()

    @staticmethod
    def set_ttl(dnspkg):
        for key, value in dnspkg.cachedata.items():
            match key:
                case "rr":
                    if configs.cache_fix:
                        dnspkg.rr.extend(value)
                    else:
                        fix = []
                        for _rr in value:
                            if _rr.rtype == QTYPE.CNAME:
                                dnspkg.rr.append(_rr)
                            elif _rr.rtype == QTYPE.A or _rr.rtype == QTYPE.AAAA or _rr.rtype == QTYPE.NS or _rr.rtype == QTYPE.MX:
                                fix.append(_rr)
                            else:
                                dnspkg.rr.append(_rr)
                        shuffle(fix)
                        dnspkg.rr.extend(fix)

                    for rr in dnspkg.rr:
                        rr.ttl = dnspkg.ttl
                case "auth":
                    dnspkg.auth.extend(value)
                    for auth in dnspkg.auth:
                        auth.ttl = dnspkg.ttl
                case "rcode":
                    if value is None:
                        dnspkg.header.set_rcode(RCODE.NOERROR)
                    else:
                        dnspkg.header.set_rcode(value)

    async def get_ttl(self):
        self.ttl = self.new_cache.getttl(self.q.qname, self.q.qtype, self.rule)
        if self.ttl is not None:
            if self.ttl < 1:
                logger.debug(f'ttl timeout, use expired reply ttl {self.configs.expired_reply_ttl}')
                self.ttl = self.configs.expired_reply_ttl
                await asyncio.create_task(self.none_cache_method(self, ttl_timeout_status=True))
                self.new_cache.deldata(self.q.qname, self.q.qtype)
        else:
            logger.debug(f'no ttl cache data, use expired reply ttl {self.configs.expired_reply_ttl}')
            self.ttl = self.configs.expired_reply_ttl
            await asyncio.create_task(self.none_cache_method(self, ttl_timeout_status=True))

    @staticmethod
    def header_setting(dnspkg):
        logger.debug(f'header_setting')
        dnspkg.response_header = dnspkg.header
        dnspkg.header.set_qr(QR.RESPONSE)
        dnspkg.header.set_ra(1)
        dnspkg.header.set_aa(1)
        dnspkg.header.set_tc(0)
        dnspkg.header.set_rcode(0)

    @staticmethod
    async def none_cache_method(dnspkg, *, ttl_timeout_status=False):
        ttl_timeout_send = share_objects.ttl_timeout_send

        dnspkg.upserver = dnspkg.configs.dnsservers.get(dnspkg.rule, dnspkg.configs.default_upstream_server)

        if dnspkg.configs.bool_fakeip and dnspkg.rule == dnspkg.configs.fakeip_match and (dnspkg.q.qtype == QTYPE.A or dnspkg.q.qtype == QTYPE.AAAA):
            # 如果查询域名为fakeip，同时查询类型为A记录或AAAA记录
            dnspkg.upserver.clear()
            dnspkg.upserver.append(dnspkg.configs.fakeip_upserver)
            dnspkg.rule = dnspkg.configs.fakeip_name_servers
            logger.debug(f'rule in fakeip modify from {dnspkg.rule} to {dnspkg.upserver}')

        logger.debug(f'get upserver select: {dnspkg.upserver}, {dnspkg.rule}, client: {dnspkg.client}')

        if ttl_timeout_status:

            pickle_data = pickle.dumps(dnspkg)
            data_amount = dnspkg.ipc_mmap.write(pickle_data)
            logger.debug(f'mmap data location: {data_amount}, client: {dnspkg.client}')

            ttl_timeout_send.send(data_amount)
            return
        else:
            data = await asyncio.create_task(query_create_tasklist(dnspkg))

        if data is not None:
            dnspkg.self_parse(data)
            dnspkg.update_cache()

    def self_parse(self, packet):
        """将从上游返回的bytes数据中，解析后修改实例属性
        """
        buffer = DNSBuffer(packet)
        try:
            header = DNSHeader.parse(buffer)
            questions = []
            self.response_header = header  # header为客户端请求时的，采用新的属性存放返回报文
            for _ in range(header.q):
                questions.append(DNSQuestion.parse(buffer))
            for _ in range(header.a):
                self.rr.append(RR.parse(buffer))
            for _ in range(header.auth):
                self.auth.append(RR.parse(buffer))
            for _ in range(header.ar):
                self.ar.append(RR.parse(buffer))
            logger.debug(f'response ar: {self.ar}')
        except DNSError:
            raise
        except (BufferError, BimapError) as e:
            raise DNSError("Error unpacking DNSRecord [offset=%d]: %s" % (buffer.offset, e))

    @staticmethod
    async def response_dns_package(dnspkg):
        if (sock := dnspkg.sock) is not None:
            client = dnspkg.client
            dnspkg.ar.clear()
            dnspkg.ar.extend(dnspkg._ar)
            data = dnspkg.pack()
            match sock.get_extra_info('socket').type:
                case socket.SOCK_STREAM:
                    data_length = len(data)
                    tcpdata = struct.pack('!H', data_length) + data
                    try:
                        sock.write(tcpdata)
                    except AttributeError as error:
                        logger.error(f'attribute error: {error}')
                    finally:
                        sock.close()
                case socket.SOCK_DGRAM:
                    sock.sendto(data, client)
                case _:
                    logger.error(
                        f"response_dns_package sock is None client: {client}, data: {data}")
            logger.debug(f"response data time")
        else:
            logger.error(
                f'socket is None client: {dnspkg.client}, dnspkg: {dnspkg.q.qname}, sock {dnspkg.sock}')


class Dnspkg_Static(DNSRecord):

    client_address = None

    __slots__ = (
        'header', 'questions', 'rr', 'auth', 'ar', 'response_header', 'rcode', '_ar', 'code_state',
        'configs', 'sockfd', 'question_packet', 'sock', 'client', 'upserver', 'rules', 'ipset_rule',
        'OPTv4', 'OPTv6', 'OPTCOOKIE', 'rulesearch', 'new_cache', 'cachedata', 'cookie', 'ipc_mmap',
    )
    def __init__(self, header=None, questions=None, rr=None, auth=None, ar=None, rule=None):
        super().__init__(header=header, questions=questions, rr=rr, auth=auth, ar=ar)
        self.new_cache = new_cache
        self.rulesearch = rulesearch
        self.sock = None
        self.client = Dnspkg_Static.client_address or None
        self.cachedata = None
        self.rule = rule
        self._ar = []

        contextvars_dnsinfo.set(
            {
                'address': self.client,
                'id': self.header.id,
                'qname': self.q.qname,
                'qtype': self.q.qtype
            }
        )
        # 上下文变量不可放在实例属性上方，因为这些属性还未初始化完成

    async def handler(self, sock, *, client=None):

        self.client = client
        self.sock = sock

        contextvars_dnsinfo.set(
            {
                'address': self.client[0] if client is not None else None,
                'id': self.header.id,
                'qname': self.q.qname,
                'qtype': self.q.qtype
            }
        )

        share_objects.history.append((time.time(), client[0], self.q.qname))

        self.cachedata = self.new_cache.getdata(self.q.qname, self.q.qtype)
        if self.cachedata is None:
            Dnspkg.header_setting(self)
            asyncio.create_task(Dnspkg.response_dns_package(self))
            return

        self.ttl = self.new_cache.getttl(self.q.qname, self.q.qtype, self.rule)
        Dnspkg.set_ttl(self)
        Dnspkg.header_setting(self)

        asyncio.create_task(Dnspkg.response_dns_package(self))
        return


class Dnspkg_FakeIP(Dnspkg):

    client_address = None

    __slots__ = (
        'header', 'questions', 'rr', 'auth', 'ar', 'response_header', 'rcode', '_ar', 'code_state',
        'configs', 'sockfd', 'question_packet', 'sock', 'client', 'upserver', 'rule', 'ipset_rule',
        'OPTv4', 'OPTv6', 'OPTCOOKIE', 'rulesearch', 'new_cache', 'cachedata', 'cookie', 'ipc_mmap',
    )
    def __init__(self, header=None, questions=None, rr=None, auth=None, ar=None, rule=None):
        super().__init__(header=header, questions=questions, rr=rr, auth=auth, ar=ar, rule=rule)
        self.new_cache = new_cache
        self.rulesearch = rulesearch
        self.sock = None
        self.client = Dnspkg_Static.client_address or None
        self.cachedata = None
        self._ar = []
        self.upserver = [configs.fakeip_upserver]

        contextvars_dnsinfo.set(
            {
                'address': self.client,
                'id': self.header.id,
                'qname': self.q.qname,
                'qtype': self.q.qtype
            }
        )
        # 上下文变量不可放在实例属性上方，因为这些属性还未初始化完成

    async def handler(self, sock, *, client=None):

        self.client = client
        self.sock = sock

        contextvars_dnsinfo.set(
            {
                'address': self.client[0] if client is not None else None,
                'id': self.header.id,
                'qname': self.q.qname,
                'qtype': self.q.qtype
            }
        )

        share_objects.history.append((time.time(), client[0], self.q.qname))

        self.cachedata = self.new_cache.getdata(self.q.qname, self.q.qtype)
        if self.cachedata is not None:
            await self.get_ttl()
            logger.debug('cacheed')
            self.rr.extend(self.cachedata.get('rr'))
            self.a.ttl = self.ttl
            Dnspkg.header_setting(self)

            self.response_header = self.header
            asyncio.create_task(Dnspkg.response_dns_package(self))
            return
        else:
            logger.debug('not cacheed')
            await asyncio.create_task(self.none_cache_method())
            self.update_ttl()
            self.new_cache.setdata(self)

            if len(self.rr) == 0 and len(self.auth) == 0:
            # 上游服务器响应内容为空时，将rcode设置为nxdomain
                self.header.set_rcode(RCODE.NXDOMAIN)
                self.new_cache.deldata(self.q.qname, self.q.qtype)

            self.header_setting(self)
            asyncio.create_task(self.response_dns_package(self))
            return

    def update_ttl(self):
        if self.a.ttl > configs.fakeip_ttl:
            self.ttl = configs.fakeip_ttl
            self.a.ttl = configs.fakeip_ttl
        self.ttl = self.a.ttl
        logger.debug(f'original rr ttl: {self.a.ttl}, fakeip ttl: {self.ttl}')
        self.new_cache.setttl(self.q.qname, self.q.qtype, self.ttl)

    def update_cache(self):
        """覆盖父类"""
        self.update_ttl()
        logger.debug('update cache')

    async def get_ttl(self):
        self.ttl = self.new_cache.getttl(self.q.qname, self.q.qtype)
        logger.debug(f'ttl: {self.ttl}')
        if self.ttl is not None:
            if self.ttl < 1:
                self.ttl = configs.expired_reply_ttl
                await asyncio.create_task(self.none_cache_method(ttl_timeout_status=True))
                self.new_cache.deldata(self.q.qname, self.q.qtype)
                logger.debug(f'ttl timeout, use expired reply ttl {configs.expired_reply_ttl}')
        else:
            logger.debug(f'no ttl cache data, use expired reply ttl {configs.expired_reply_ttl}')
            self.ttl = configs.expired_reply_ttl
            await asyncio.create_task(self.none_cache_method(ttl_timeout_status=True))

    async def none_cache_method(self, *, ttl_timeout_status=False):
        ttl_timeout_send = share_objects.ttl_timeout_send

        self.rule = configs.fakeip_name_servers
        logger.debug(f'get upserver select: {self.upserver}, {self.rule}, client: {self.client}')

        if ttl_timeout_status:

            pickle_data = pickle.dumps(self)
            data_amount = self.ipc_mmap.write(pickle_data)
            logger.debug(f'mmap data location: {data_amount}, client: {self.client}')

            ttl_timeout_send.send(data_amount)
            return
        else:
            data = await asyncio.create_task(query_create_tasklist(self))

        if data is not None:
            self.self_parse(data)
            self.new_cache.setdata(self)


class Dnspkg_BlackList(DNSRecord):

    client_address = None

    def __init__(self, header=None, questions=None, rr=None, auth=None, ar=None, rule=None):
        super().__init__(header=header, questions=questions, rr=rr, auth=auth, ar=ar)
        self.configs = configs
        self._ar = []
        self.client = Dnspkg_BlackList.client_address or None

        contextvars_dnsinfo.set(
            {
                'address': self.client,
                'id': self.header.id,
                'qname': self.q.qname,
                'qtype': self.q.qtype
            }
        )

    async def handler(self, sock, *, client=None):

        self.client = client
        self.sock = sock

        contextvars_dnsinfo.set(
            {
                'address': self.client[0] if client is not None else None,
                'id': self.header.id,
                'qname': self.q.qname,
                'qtype': self.q.qtype
            }
        )

        share_objects.history.append((time.time(), client[0], self.q.qname))

        logger.debug(f'config blacklist rcode: {self.configs.blacklist_rcode}')
        self.response_header = self.header
        match self.configs.blacklist_rcode:
            case 'success':
                self.add_answer(
                    RR(
                        self.q.qname,
                        QTYPE.CNAME,
                        rdata=CNAME(self.configs.BLACKLIST_MNAME), ttl=self.configs.ttl_max)
                    )

                self.add_auth(
                    RR(
                        self.configs.BLACKLIST_MNAME,
                        QTYPE.SOA,
                        rdata=SOA(
                            self.configs.BLACKLIST_MNAME,
                            self.configs.BLACKLIST_RNAME,
                            (1800, 1800, 900, 604800, 86400)),
                            ttl=self.configs.ttl_max
                        )
                    )
                self.header.set_rcode(0)
            case 'format_error':
                self.header.set_rcode(1)
            case 'refused':
                self.header.set_rcode(5)
            case 'server_failure':
                self.header.set_rcode(2)
            case 'nxdomain':
                self.header.set_rcode(3)
            case 'notimp':
                self.header.set_rcode(4)

        Dnspkg.header_setting(self)
        asyncio.create_task(Dnspkg.response_dns_package(self))
        return


class Dnspkg_SOA(Dnspkg):
    def __init__(self, header=None, questions=None, rr=None, auth=None, ar=None):
        super().__init__(header=header, questions=questions, rr=rr, auth=auth, ar=ar)

    async def handler(self, sock, *, client=None):
        self.client = client
        self.sock = sock

        contextvars_dnsinfo.set(
            {
                'address': self.client[0] if client is not None else None,
                'id': self.header.id,
                'qname': self.q.qname,
                'qtype':self.q.qtype 
            }
        )

        share_objects.history.append((time.time(), client[0], self.q.qname))

        logger.debug(f'query name in soa list')
        # 请求类型qtype在SOA列表的执行方法
        self.header_setting(self)
        asyncio.create_task(self.response_dns_package(self))
        return


class QueueHandler(Dnspkg):

    client_address = None

    def __init__(self, header=None, questions=None, rr=None, auth=None, ar=None, rule=None):
        super().__init__(header=header, questions=questions, rr=rr, auth=auth, ar=ar, rule=rule)
        self.new_cache = new_cache
        self.rulesearch = rulesearch
        self.upserver = None

        logger.debug('generate dns object')
        self.cachedata = self.new_cache.getdata(self.q.qname, self.q.qtype)
        logger.debug(f'get cache time')

    @classmethod
    def parse(cls, packet, **kwargs):
        cls.rule = None
        buffer = DNSBuffer(packet)
        try:
            header = DNSHeader.parse(buffer)
            questions = []
            rr = []
            auth = []
            ar = []
            for _ in range(header.q):
                questions.append(DNSQuestion.parse(buffer))
            for _ in range(header.a):
                rr.append(RR.parse(buffer))
            for _ in range(header.auth):
                auth.append(RR.parse(buffer))
            for _ in range(header.ar):
                ar.append(RR.parse(buffer))

            if questions[0].qtype in configs.soa_list:
                return Dnspkg_SOA(header,questions,rr,auth=auth,ar=ar)

            cls.rule = rulesearch.search(str(questions[0].qname), repositorie='upstreams-checkpoint')

            if cls.rule in configs.blacklist:
                return Dnspkg_BlackList(header,questions,rr,auth=auth,ar=ar,rule=cls.rule)
            elif cls.rule == share_objects.STATIC_RULE:
                return Dnspkg_Static(header,questions,rr,auth=auth,ar=ar,rule=cls.rule)
            elif cls.rule == configs.fakeip_match and \
                (questions[0].qtype == QTYPE.A or questions[0].qtype == QTYPE.AAAA) and \
                    configs.bool_fakeip:
                return Dnspkg_FakeIP(header,questions,rr,auth=auth,ar=ar,rule=cls.rule)

            return cls(header,questions,rr,auth=auth,ar=ar,rule=cls.rule)
        except DNSError:
            raise
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking DNSRecord [offset=%d]: %s" % (buffer.offset,e))

    async def handler(self, sock, *, client=None):
        self.client = client
        self.sock = sock

        share_objects.history.append((time.time(), client[0], self.q.qname))

        contextvars_dnsinfo.set(
            {
                'address': self.client[0] if client is not None else None,
                'id': self.header.id,
                'qname': self.q.qname,
                'qtype':self.q.qtype 
            }
        )

        if self.cachedata:
            """self.cachedata:
            [
                [<DNS RR: 'gw.example.org.' rtype=A rclass=IN ttl=0 rdata='192.168.8.1'>],
                [<DNS AUTH: ... ...>],
                [<DNS AR: ... ...>],
                <DNS RCODE>
            ]
            or
            None
            """

            await self.get_ttl()
            self.set_ttl(self)
            self.header_setting(self)

            asyncio.create_task(self.response_dns_package(self))
            return

        else:
            await asyncio.create_task(self.none_cache_method(self))

            if len(self.rr) == 0 and len(self.auth) == 0:
            # 上游服务器响应内容为空时，将rcode设置为nxdomain
                self.header.set_rcode(RCODE.NXDOMAIN)
                self.new_cache.deldata(self.q.qname, self.q.qtype)

            self.header_setting(self)
            asyncio.create_task(self.response_dns_package(self))
            return

