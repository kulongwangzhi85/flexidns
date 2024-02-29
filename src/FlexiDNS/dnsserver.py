
# coding: utf-8

"""
dns服务进程，接收来自客户端的dns请求
"""

import asyncio
import copy
import os
import pickle
import signal
import socket
import struct

from importlib.util import find_spec
from importlib import reload
from functools import partial
from itertools import zip_longest
from logging import getLogger

from dnslib import RCODE, EDNSOption, QTYPE, DNSRecord, QR, SOA, RR, CNAME, DNSError, DNSBuffer, DNSQuestion, DNSHeader, BimapError, EDNS0

from .tomlconfigure import configs, share_objects
from .dnscache import new_cache
from .dnsrules_new import rulesearch, iprepostitory
from .dnslog import dnsidAdapter
from .dnsupstream import query_create_tasklist
from .dnsmmap_ipc import CircularBuffer

logger = getLogger(__name__)
contextvars_dnsinfo = share_objects.contextvars_dnsinfo
logger = dnsidAdapter(logger, {'dnsinfo': contextvars_dnsinfo})

try:
    import ssl
except ImportError:
    logger.error("import ssl module is not installed")

if True and find_spec('uvloop'):
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

asyncio_event = asyncio.Event()  # 阻塞start_tasks方法
asyncio_event.clear()


async def write_wait(writer):
    await writer.wait_closed()


class QueueHandler(DNSRecord):

    client_address = None

    __slots__ = (
        'header', 'questions', 'rr', 'auth', 'ar', 'response_header', 'rcode', '_ar', 'code_state',
        'configs', 'sockfd', 'question_packet', 'sock', 'client', 'upserver', 'rules',
        'OPTv4', 'OPTv6', 'OPTCOOKIE', 'rulesearch', 'new_cache', 'cachedata', 'cookie'
    )

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
            case 'ipc_mmap':
                setattr(self, 'ipc_mmap', ipc_mmap)
                return getattr(self, name)

    def __init__(self, header=None, questions=None, rr=None, auth=None, ar=None):
        self.new_cache = new_cache
        self.rulesearch = rulesearch
        self.configs = configs
        self.upserver = None
        self.sock = None
        self.client = QueueHandler.client_address or None
        self.edns0 = []
        self.cachedata = None

        self.header = header
        self.response_header = None
        self.questions = questions
        self.rr = rr or []
        self.auth = auth or []
        self._ar = ar or []
        self.ar = []
        self.rules = None
        self.code_state = [ True, True ] # [ code8, code10 ]
        self.cookie = None


        contextvars_dnsinfo.set(
            {
                'address': self.client,
                'id': self.header.id,
                'qname': self.q.qname,
                'qtype': self.q.qtype
            }
        )
        # 上下文变量不可放在实例属性上方，因为这些属性还未初始化完成

        logger.debug('generate dns object')
        self.cachedata = self.new_cache.getdata(self.q.qname, self.q.qtype)
        logger.debug(f'get cache time ar {self._ar}')

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

    @classmethod
    def parse(cls, packet, **kwargs):
        if kwargs:
            cls.client_address = kwargs['address']
        return super(QueueHandler, cls).parse(packet)

    def pack(self):
        return super().pack()

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

        if self.rules == self.configs.fakeip_name_servers:
            for i in self.rr:
                if i.ttl >= self.configs.fakeip_ttl:
                    rrttl = self.configs.fakeip_ttl
                    i.ttl = self.configs.fakeip_ttl
                else:
                    rrttl = i.ttl
            self.new_cache.setttl(self.q.qname, self.q.qtype, rrttl, 'fakeip')
            self.new_cache.setdata(self)
        else:
            rrttl = 0
            min_ttl = self.configs.ttl_min
            max_ttl = self.configs.ttl_max

            for rr, auth in zip_longest(self.rr, self.auth, fillvalue=None):

                if rr:
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

    async def none_cache_method(self, *, ttl_timeout_status=False):
        ttl_timeout_send = share_objects.ttl_timeout_send

        self.upserver = self.configs.dnsservers.get(self.rules, self.configs.default_upstream_server)

        if self.configs.bool_fakeip and self.rules == self.configs.fakeip_match and (self.q.qtype == QTYPE.A or self.q.qtype == QTYPE.AAAA):
            # 如果查询域名为fakeip，同时查询类型为A记录或AAAA记录
            self.upserver.clear()
            self.upserver.append(self.configs.fakeip_upserver)
            self.rules = self.configs.fakeip_name_servers
            logger.debug(f'rule in fakeip modify from {self.rules} to {self.upserver}')

        logger.debug(f'get upserver select: {self.upserver}, {self.rules}, client: {self.client}')

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
            ipset_check_result = ipset_checkpoint(self)
            if ipset_check_result or ipset_check_result is None:
                logger.debug(f'ipset_check_result: {ipset_check_result}')
            self.update_cache()

    def soa_method(self):
        # 用于返回各种rcode方法

        logger.debug(self.configs.blacklist_rcode)
        self.response_header = self.header
        match self.configs.blacklist_rcode:
            case 'success':
                self.add_answer(RR(self.q.qname, QTYPE.CNAME, rdata=CNAME("a.gtld-servers.net"), ttl=self.configs.ttl_max))
                self.add_auth(RR("a.gtld-servers.net", QTYPE.SOA, rdata=SOA("a.gtld-servers.net","nstld.verisign-grs.com", (1800, 1800, 900, 604800, 86400)), ttl=self.configs.ttl_max))
                self.header.set_rcode(0)
                self.new_cache.setdata(self)
                self.new_cache.setttl(self.q.qname, self.q.qtype, self.configs.ttl_max)
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
        self.header.set_qr(QR.RESPONSE)
        self.header.set_ra(1)
        self.header.set_aa(1)
        self.header.set_tc(0)
        return self

    def none_method(self):
        logger.debug(f'none_method')
        self.response_header = self.header
        self.header.set_qr(QR.RESPONSE)
        self.header.set_ra(1)
        self.header.set_aa(1)
        self.header.set_rcode(4)

    async def handler(self, sock, *, client=None):
        self.client = client
        self.sock = sock
        configs = self.configs
        expired_reply_ttl = configs.expired_reply_ttl
        header = self.header
        query_name = self.q.qname
        query_type = self.q.qtype
        query_id = header.id

        self.rules = self.rulesearch.search(str(query_name), repositorie='upstreams-checkpoint')
        logger.debug(f'rules: {self.rules}')

        contextvars_dnsinfo.set(
            {
                'address': self.client[0] if client is not None else None,
                'id': query_id,
                'qname': query_name,
                'qtype': query_type
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

            cachettl = self.new_cache.getttl(query_name, query_type, self.rules)
            logger.debug(f'ttl: {cachettl}')

            if cachettl is not None:
                if self.rules in configs.blacklist and cachettl <= 1:
                    """qname is in blacklist, use ttl_max"""

                    cachettl = configs.ttl_max
                    self.new_cache.setttl(query_name, query_type, configs.ttl_max)
                elif cachettl <= expired_reply_ttl:
                    """cache ttl expired, use expired reply ttl"""

                    logger.debug(f'ttl timeout, use expired reply ttl {expired_reply_ttl}')
                    cachettl = expired_reply_ttl
                    await asyncio.create_task(self.none_cache_method(ttl_timeout_status=True))
                    self.new_cache.deldata(query_name, query_type)
            else:
                logger.debug(f'no ttl cache data, use expired reply ttl {expired_reply_ttl}')
                cachettl = expired_reply_ttl
                await asyncio.create_task(self.none_cache_method(ttl_timeout_status=True))

            for key, value in self.cachedata.items():
                match key:
                    case "rr":
                        self.rr.extend(value)
                        for rr in self.rr:
                            rr.ttl = cachettl
                    case "auth":
                        self.auth.extend(value)
                        for auth in self.auth:
                            auth.ttl = cachettl
                    case "rcode":
                        if value is None:
                            header.set_rcode(RCODE.NOERROR)
                        else:
                            header.set_rcode(value)

            header.set_qr(QR.RESPONSE)
            header.set_ra(1)
            header.set_aa(1)
            header.set_tc(0)

            asyncio.create_task(response_dns_package(self))
            return

        elif query_type in configs.soa_list:
            logger.debug(f'query name in soa list')
            # 请求类型qtype在SOA列表的执行方法
            self.none_method()
            asyncio.create_task(response_dns_package(self))
            return

        elif self.rules in configs.blacklist:
            # 请求域名在黑名单列表的执行方法
            self.soa_method()
            asyncio.create_task(response_dns_package(self))
            return

        elif self.rules == configs.static_rule:
            # 这个用于阻止相应的static_cache表的静态域名列表，当请求A记录时，会同时请求AAAA记录
            # 以及处理hosts类似静态记录的处理

            logger.debug(f'hostname: {configs.static_rule}')
            header.set_qr(QR.RESPONSE)
            header.set_ra(1)
            header.set_aa(1)
            header.set_tc(0)

            asyncio.create_task(response_dns_package(self))
            return

        else:
            await asyncio.create_task(self.none_cache_method())

            if len(self.rr) == 0 and len(self.auth) == 0:
            # 上游服务器响应内容为空时，将rcode设置为nxdomain
                header.set_rcode(RCODE.NXDOMAIN)
                self.new_cache.deldata(query_name, query_type)

            header.set_qr(QR.RESPONSE)
            header.set_ra(1)
            header.set_aa(1)
            header.set_tc(0)

            asyncio.create_task(response_dns_package(self))
            return


async def response_dns_package(dnspkg):
    if (sock := dnspkg.sock) is not None:
        client = dnspkg.client
        dnspkg.ar.clear()
        dnspkg.ar.extend(dnspkg._ar)
        logger.debug(f'dnspkg ar {dnspkg.ar}')
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


class DnsServerDatagramProtocol(asyncio.DatagramProtocol):
    """udp协议类
    """

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            dnspkg = QueueHandler.parse(data, address=addr[0])
            logger.debug(f"udp recv a dns question packet")
        except DNSError as error:
            contextvars_dnsinfo.set({'address': addr[0], 'id': None, 'qname': None, 'qtype': None})
            logger.error(f"udp recv not a dns packet: {error} client addr {addr[0]} port {addr[1]}")
            logger.error(f"udp packet: {data}")
        except OSError as error:
            contextvars_dnsinfo.set({'address': addr[0], 'id': None, 'qname': None, 'qtype': None})
            logger.error(f"udp recv not a dns packet: {error} client addr {addr[0]} port {addr[1]}")
            logger.error(f"udp packet: {data}")
        else:
            asyncio.create_task(dnspkg.handler(self.transport, client=addr))

    def connection_lost(self, exc):
        if exc is not None:
            sockpeername = self.transport.get_extra_info('peername')
            logger.error(f'Error from {sockpeername}: {exc}')
            if not self.on_con_lost.done():
                self.on_con_lost.set_exception(exc)


class DnsServerDatastramProtocol(asyncio.Protocol):
    """tcp协议类
    """

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        try:
            client = self.transport.get_extra_info('peername')
            dnspkg = QueueHandler.parse(data[2:], address=client[0])
            logger.debug(f"tcp recv a dns question packet")
        except DNSError as error:
            contextvars_dnsinfo.set({'address': None, 'id': None, 'qname': None, 'qtype': None})
            logger.error(f"tcp recv not a dns packet: {error}")
            self.transport.close()
        except OSError as error:
            contextvars_dnsinfo.set({'address': None, 'id': None, 'qname': None, 'qtype': None})
            logger.error(f"tcp recv not a dns packet: {error}")
            self.transport.close()
        else:
            asyncio.create_task(dnspkg.handler(self.transport, client=client))


class CommandUnixProtocol:
    """用于命令行下asyncio启动的AF_UNIX服务实现协议
    """

    def __init__(self):
        from .dnscli import commandmmap
        self.commandmmap = commandmmap
        self.transport = None
        self.data_length = None

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, command):
        logger.debug(f'Command Unix Recv: {command}')
        data_length = self.commandmmap.receving(command)
        logger.debug(f'received data length: {data_length}')
        self.transport.write(data_length)
        self.transport.write_eof()

    def error_received(self, exc):
        logger.debug(f'Error received: {exc}')

    def eof_received(self):
        self.transport.close()

    def connection_lost(self, exc):
        if exc is not None:
            logger.debug(f'asyncio Connection closed error {exc}')
        self.transport.close()


class DnsOverTLSServerProtocol(asyncio.Protocol):
    """tcp协议类
    dot tcp 853 server protocol
    Noto: 其实可共用原始tcp协议类, 使用loop.start_tls方法
    """

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        try:
            dnspkg = QueueHandler.parse(data[2:])
            logger.debug(f"dot recv a dns question packet")
        except ssl.SSLError as error:
            contextvars_dnsinfo.set({'address': None, 'id': None, 'qname': None, 'qtype': None})
            logger.error(f"dot recv not a dns packet: {error}")
            self.transport.close()
            return
        except DNSError as error:
            contextvars_dnsinfo.set({'address': None, 'id': None, 'qname': None, 'qtype': None})
            logger.error(f"dot recv not a dns packet: {error}")
            self.transport.close()
            return
        except OSError as error:
            contextvars_dnsinfo.set({'address': None, 'id': None, 'qname': None, 'qtype': None})
            logger.error(f"dot recv not a dns packet: {error}")
            self.transport.close()
            return
        else:
            asyncio.create_task(dnspkg.handler(
                self.transport, client=self.transport.get_extra_info('peername')))


def exit_process(signal, loop):
    from .dnspickle import serialize
    from .dnsrules_new import rulesearch
    from .dnscache import new_cache

    from .tomlconfigure import share_objects
    stop_message = share_objects.ttl_timeout_send
    stop_message.send(None)

    if configs.cache_persist:
        serialize(new_cache, rulesearch)

    asyncio_event.set()

def ipset_checkpoint(data: QueueHandler) -> bool:
    """
    用于域名防污染使用
    根据set-usage，检查域名与IP地址
    todo NOTE: 后期可能使用yield改造
    改造思路：如果一个域名返回多个ip，如何某个ip经过检查返回False，则pop，并进行下一个ip的检查
    """

    if (ipset_rule:= data.ipset_rule):
        for rr in data.rr:
            if rr.rtype == QTYPE.A:
                if ipset_status:= iprepostitory.search(str(rr.rdata), repositorie=ipset_rule):
                    return ipset_status
            elif rr.rtype == QTYPE.AAAA:
                if ipset_status:= iprepostitory.search(str(rr.rdata), repositorie=ipset_rule):
                    return ipset_status

def ttlout_update_cache(read_fd):
    """ttl过期更新使用
    接收dnsttlout进程返回的dns报文

    Arguments:
        read_fd {os.pipe}: 管道读端,接收来自dnsttlout进程的dns报文
    """
    data_prefix = os.read(read_fd, 2)
    if not data_prefix:
        return
    data_prefix_length = struct.unpack('!H', data_prefix)[0]
    data_prefix_struct = os.read(read_fd, data_prefix_length)
    data_amount = pickle.loads(data_prefix_struct)
    logger.debug(f'receive mmap data location: {data_amount}')
    data_raw = ipc_01_mmap.read(data_amount)
    try:
        dnspkg = pickle.loads(data_raw)
    except DNSError as error:
        logger.error(
            f"update error not a dns packet data: {data_raw}, data_prefix: {data_prefix}")
    except OSError as error:
        logger.error("update error not a dns packet")
    else:
        contextvars_dnsinfo.set({
            'address': dnspkg.client,
            'id': dnspkg.header.id,
            'qname': dnspkg.q.qname,
            'qtype': dnspkg.q.qtype
        })
        logger.debug(f'ttl timeout update cache data')
        # ipset_check_result = ipset_checkpoint(dnspkg)
        # if ipset_check_result or ipset_check_result is None:
        #     logger.debug(f'ipset_check_result: {ipset_check_result}')
        dnspkg.update_cache()


async def start_tasks():
    """启动asyncio服务
    """
    loop = asyncio.get_running_loop()
    for signame in {'SIGINT', 'SIGTERM'}:
        loop.add_signal_handler(
            getattr(signal, signame),
            partial(exit_process, signame, loop))

    ttl_timeout_response_recv = share_objects.ttl_timeout_response_recv
    loop.add_reader(ttl_timeout_response_recv,
                    lambda: ttlout_update_cache(ttl_timeout_response_recv))
    socket_file = configs.sockfile
    if os.path.exists(socket_file):
        os.remove(socket_file)
    unixsrv = await loop.create_unix_server(lambda: CommandUnixProtocol(), path=socket_file)
    await unixsrv.start_serving()

    for i in configs.server:
        for k, v in i.items():
            match k:
                case 'udp':
                    logger.debug(
                        f'starting udp server, interfaces {v[0]}, port {v[1]}')
                    udpsrv_transport, _ = await loop.create_datagram_endpoint(
                        lambda: DnsServerDatagramProtocol(),
                        local_addr=(v[0], v[1])
                    )
                case 'tcp':
                    logger.debug(
                        f'starting tcp server, interfaces {"all" if v[0] is None or v[0] == "::" else v[0]}, port {v[1]}')
                    tcpsrv = await loop.create_server(lambda: DnsServerDatastramProtocol(), host=v[0], port=v[1])
                    await tcpsrv.start_serving()
                case 'dot':
                    logger.debug(
                        f'starting dot server, interfaces {"all" if v[0] is None or v[0] == "::" else v[0]}, port {v[1]}')
                    ssl_context = ssl.create_default_context(
                        ssl.Purpose.CLIENT_AUTH, cafile=configs.tls_cert_ca)
                    ssl_context.load_cert_chain(
                        certfile=configs.tls_cert, keyfile=configs.tls_cert_key)
                    dotsrv = await loop.create_server(lambda: DnsOverTLSServerProtocol(), host=v[0], port=v[1], ssl=ssl_context)
                    await dotsrv.start_serving()

    try:
        logger.debug('start asyncio server')
        await asyncio_event.wait()
    finally:

        try:
            udpsrv_transport.close()
            tcpsrv.close()
            await tcpsrv.wait_closed()
            dotsrv.close()
            await dotsrv.wait_closed()
        except UnboundLocalError as error:
            pass

        ipc_mmap.mm.close()
        logger.debug('stop asyncio server')


def start():
    global ipc_mmap, ipc_01_mmap, rulesearch, iprepostitory, new_cache

    if rulesearch is None:
        rulesearch = reload(rulesearch)
    if iprepostitory is None:
        iprepostitory = reload(iprepostitory)
    if new_cache is None:
        new_cache = reload(new_cache)

    ipc_mmap = CircularBuffer(ipc_mmap=share_objects.ipc_mmap, ipc_mmap_size=share_objects.ipc_mmap_size)
    ipc_01_mmap = CircularBuffer(ipc_mmap=share_objects.ipc_01_mmap, ipc_mmap_size=share_objects.ipc_mmap_size)
    logger.debug(f'upstream dnsserver is {configs.dnsservers}')
    logger.debug(f'edns0 ipv4 is {configs.edns0_ipv4_address}, ipv6 is {configs.edns0_ipv6_address}')
    asyncio.run(start_tasks())
