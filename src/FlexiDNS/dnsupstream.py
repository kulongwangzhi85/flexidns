
# coding: utf-8

"""
该模块用于定义上游各种协议实现部分
"""

import asyncio
import struct
from typing import Optional, cast
from logging import getLogger

from dnslib import DNSRecord
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived

from .dnslog import dnsidAdapter
from .tomlconfigure import share_objects

logger = getLogger(__name__)
logger = dnsidAdapter(logger, {'dnsinfo': share_objects.contextvars_dnsinfo})

try:
    import ssl
except ImportError:
    logger.error("import ssl module is not installed")


class DnsClientQuicProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._ack_waiter: Optional[asyncio.Future[DNSRecord]] = None

    async def query(self, dnspkg):
        # serialize query
        data = struct.pack("!H", len(dnspkg)) + dnspkg

        # send query and wait for answer
        stream_id = self._quic.get_next_available_stream_id()
        self._quic.send_stream_data(stream_id, data, end_stream=True)
        waiter = self._loop.create_future()
        self._ack_waiter = waiter
        self.transmit()

        return await asyncio.shield(waiter)

    def quic_event_received(self, event: QuicEvent) -> None:
        if self._ack_waiter is not None:
            if isinstance(event, StreamDataReceived):
                # parse answer
                length = struct.unpack("!H", bytes(event.data[:2]))[0]
                data = event.data[2: 2 + length]

                # return answer
                waiter = self._ack_waiter
                self._ack_waiter = None
                waiter.set_result(data)


async def dnsoverquic_query_tasks(dnspkg, server) -> None:
    # configuration: QuicConfiguration,

    configuration = QuicConfiguration(alpn_protocols=["doq"], is_client=True)
    configuration.verify_mode = ssl.CERT_NONE

    if server[3] is not None and 'edns0' in server[3]:
        before_dnspkg = dnspkg._edns0()
    else:
        before_dnspkg = dnspkg.pack()

    logger.debug(f"connecting to {server[0]}:{server[1]}")
    async with connect(
        server[0],
        server[1],
        configuration=configuration,
        session_ticket_handler=None,
        create_protocol=DnsClientQuicProtocol,
    ) as client:
        client = cast(DnsClientQuicProtocol, client)
        logger.debug("sending dns query")
        response_dnspkg = await client.query(before_dnspkg)
        logger.info(f"received dns data {response_dnspkg}")
        if response_dnspkg is not None:
            return response_dnspkg


async def write_wait(writer):
    try:
        await writer.wait_closed()
    except  ConnectionResetError:
        logger.debug('asyncio Connection refused error')


async def datastream_query_tasks(dnspkg, server):
    """tcp查询
    """
    data = bytearray()
    logger.debug(f'server {server[0]} edns0 ext: {server[3]}')
    reader, writer = await asyncio.open_connection(host=server[0], port=server[1])

    if server[3] is not None and 'edns0' in server[3]:
        before_data = dnspkg._edns0()
    else:
        before_data = dnspkg.pack()

    data_send = struct.pack('!H', len(before_data)) + before_data
    writer.write(data_send)
    await writer.drain()

    try:
        bytes_struct_package_length = await reader.read(2)
    except ConnectionResetError:
        logger.error(f'Connection refused error, remote server: {server[0]}') 
    else:
        struct_package_length = struct.unpack('!H', bytes_struct_package_length)[0]
        data.extend(await reader.read(struct_package_length))
        logger.debug(f'asyncio received dns over tcp data')
    finally:
        writer.close()

    asyncio.create_task(write_wait(writer))

    if len(data) > 0:
        return data


async def dnsovertls_query_tasks(dnspkg, server, future):

    """dns over tls客户端
    """
    logger.debug(f'server {server[0]} edns0 ext: {server[3]}')
    tlscontext = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    tlscontext.minimum_version = ssl.TLSVersion.TLSv1_3
    tlscontext.maximum_version = ssl.TLSVersion.TLSv1_3

    if server[3] is not None and 'edns0' in server[3]:
        before_data = dnspkg._edns0()
    else:
        before_data = dnspkg.pack()

    logger.debug('asyncio Connection, query dns over tls')

    try:
        reader, writer = await asyncio.open_connection(ssl=tlscontext, host=server[0], port=server[1])
    except (ConnectionRefusedError, ConnectionResetError, ConnectionAbortedError) as error:
        logger.error(f'asyncio Connection refused error: {error}')
        future.set_exception(error)

    else:
        data_send = struct.pack('!H', len(before_data)) + before_data
        writer.write(data_send)
        await writer.drain()

        bytes_struct_package_length = await reader.read(2)
        struct_package_length = struct.unpack(
            '!H', bytes_struct_package_length)[0]
        data = await reader.read(struct_package_length)
        logger.debug(f'asyncio received dns over tls data: {data}')

        writer.close()

        asyncio.create_task(write_wait(writer))

        if isinstance(data, bytes):
            return data


class DnsClientDatagramProtocol(asyncio.DatagramProtocol):
    """
    UDP协议实现
    """

    def __init__(self, dnspkg, on_con_lost):
        self.data = dnspkg
        self.on_con_lost = on_con_lost
        self.transport = None

    def connection_made(self, transport):
        logger.debug(f"send datatime record")
        self.transport = transport
        self.transport.sendto(self.data)

    def datagram_received(self, data, addr):
        logger.debug(f"receive data from {addr}")
        try:
            if isinstance(data, bytes) and not self.on_con_lost.done():
                """调用future.done()方法，判断future执行任务是否已经完成，not 取反表示未完成。
                如果不做判断，会有概率发生future状态异常
                """
                self.on_con_lost.set_result(data)
        except OSError as e:
            # 处理底层网络错误
            logger.error(
                f"An OSError occurred while processing data from {addr}: {e}")
            self.on_con_lost.cancel()
            return
        except asyncio.CancelledError:
            # 处理任务被取消的情况
            logger.error(
                f"Task was cancelled while processing data from {addr}")
            self.on_con_lost.cancel()
            return
        except Exception as e:
            # 处理其他异常
            logger.error(
                f"An error occurred while processing data from {addr}: {e}")
            self.on_con_lost.cancel()
            return

    def error_received(self, exc):
        # 数据报协议UDP检测到无法将数据报传给接收方等极少数情况下被调用
        # udp 报文发送数据到服务器时，如果服务器无法接收该udp报文，会发送ICMP信息到。
        # 如果本端ICMP放行。会在此调用该方法，会抛出异常Connection refused
        if exc is not None:
            sockpeername = self.transport.get_extra_info('peername')
            logger.error(f'Error from {sockpeername}: {exc}')
            if not self.on_con_lost.done():
                self.on_con_lost.set_exception(exc)

    def connection_lost(self, exc):
        if exc is not None:
            sockpeername = self.transport.get_extra_info('peername')
            logger.error(f'Error from {sockpeername}: {exc}')
            if not self.on_con_lost.done():
                self.on_con_lost.set_exception(exc)
        self.transport.close()


async def datagram_query_tasks(dnspkg, server):
    """数据报udp协议
    """
    logger.debug(f'server {server[0]} edns0 ext: {server[3]}')

    loop = asyncio.get_running_loop()
    on_con_lost = loop.create_future()

    transport, _ = await loop.create_datagram_endpoint(
        lambda: DnsClientDatagramProtocol(dnspkg._edns0(), on_con_lost) if server[3] is not None and 'edns0' in server[3] else DnsClientDatagramProtocol(dnspkg.pack(), on_con_lost), remote_addr=(server[0], server[1]))
    try:
        result = await on_con_lost
    except Exception as error:
        logger.error(f'future result error: {error}')
    else:
        return result
    finally:
        transport.close()


async def query_create_tasklist(dnspkg, *args):
    """创建向上游DNS查询的任务列表
    NOTE: 只要有一个返回结构，任务列表立即停止。所以有时会看不到例如tcp，tls等比较慢的协议发起日志
    """
    loop = asyncio.get_running_loop()
    future = loop.create_future()

    result = None
    tasks = []
    upserver = dnspkg.upserver
    if upserver is None or len(upserver) == 0:
        logger.error(f'sender upservers: {upserver}')
        upserver = dnspkg.configs.default_upstream
    for i in upserver:
        match i[2]:
            case "udp":
                tasks.append(asyncio.create_task(
                    datagram_query_tasks(dnspkg, i)))
            case "tcp":
                tasks.append(asyncio.create_task(
                    datastream_query_tasks(dnspkg, i)))
            case "dot":
                tasks.append(asyncio.create_task(
                    dnsovertls_query_tasks(dnspkg, i, future)))
            case "doq":
                tasks.append(asyncio.create_task(
                    dnsoverquic_query_tasks(dnspkg, i)))
    logger.debug(f'tasks: {tasks}')
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED, timeout=dnspkg.configs.timeout)
    for task in pending:
        task.cancel()

    result = await asyncio.gather(*done, return_exceptions=False)
    if (result_len := len(result)) > 0:
        logger.debug(f'upstreams response results: {result_len}')
        return result[0]
