
# coding: utf-8

"""
dns服务进程，接收来自客户端的dns请求
"""

import asyncio
import os
import pickle
import signal
import socket
import struct

from importlib.util import find_spec
from functools import partial
from logging import getLogger

from dnslib import QTYPE, DNSError

from .dnstoml import configs, share_objects
from .dnslog import dnsidAdapter
from .dnspkg import QueueHandler

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
        data = pickle.dumps(self.commandmmap.receving(command))
        self.transport.write(data)
        self.transport.write_eof()

    def error_received(self, exc):
        logger.error(f'Error received: {exc}')

    def eof_received(self):
        self.transport.close()

    def connection_lost(self, exc):
        if exc is not None:
            logger.error(f'asyncio Connection closed error {exc}')
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

    from .dnstoml import share_objects
    stop_message = share_objects.ttl_timeout_send
    stop_message.send(None)

    if configs.cache_persist:
        serialize(None, new_cache, rulesearch)

    asyncio_event.set()

# def ipset_checkpoint(data: QueueHandler) -> bool:
#     """
#     用于域名防污染使用
#     根据set-usage，检查域名与IP地址
#     todo NOTE: 后期可能使用yield改造
#     改造思路：如果一个域名返回多个ip，如何某个ip经过检查返回False，则pop，并进行下一个ip的检查
#     """

#     if (ipset_rule:= data.ipset_rule):
#         for rr in data.rr:
#             if rr.rtype == QTYPE.A:
#                 if ipset_status:= iprepostitory.search(str(rr.rdata), repositorie=ipset_rule):
#                     return ipset_status
#             elif rr.rtype == QTYPE.AAAA:
#                 if ipset_status:= iprepostitory.search(str(rr.rdata), repositorie=ipset_rule):
#                     return ipset_status

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
    socket_file = share_objects.SOCKFILE
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
    global ipc_mmap, ipc_01_mmap
    ipc_mmap = share_objects.ipc
    ipc_01_mmap = share_objects.ipc_01

    logger.debug(f'upstream dnsserver is {configs.dnsservers}')
    logger.debug(f'edns0 ipv4 is {configs.edns0_ipv4_address}, ipv6 is {configs.edns0_ipv6_address}')
    asyncio.run(start_tasks())
