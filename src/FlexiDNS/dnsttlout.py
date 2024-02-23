
# coding: utf-8

"""
用于ttl过期时，从该进程发起查询。独立于dnsserver进程
NOTE：如果开启缓存，再次重启服务。由于未缓存ttl，因此重启后的ttl都是过期的，也就是重启后，缓存域名都会经过该进程发起请求，来更新缓存
"""

import asyncio
import pickle
import struct

from os import write
from logging import getLogger
from collections import namedtuple

from .dnslog import dnsidAdapter
from .tomlconfigure import share_objects
from .dnsmmap_ipc import CircularBuffer

logger = getLogger(__name__)

contextvars_dnsinfo = share_objects.contextvars_dnsinfo
logger = dnsidAdapter(logger, {'dnsinfo': contextvars_dnsinfo})

async def start_tasks():
    global logger
    from .dnsupstream import query_create_tasklist

    ttl_timeout_recv = share_objects.ttl_timeout_recv
    ttl_timeout_response_send_fd = share_objects.ttl_timeout_response_send
    
    ipc_mmap = CircularBuffer(ipc_mmap=share_objects.ipc_mmap, ipc_mmap_size=share_objects.ipc_mmap_size)

    while True:
        rece_data_amount = ttl_timeout_recv.recv()
        if rece_data_amount is not None:
            logger.debug(f'receive mmap data location: {rece_data_amount}')
            dns_packaged = ipc_mmap.read(rece_data_amount)

            dnspkg = pickle.loads(dns_packaged)

            contextvars_dnsinfo.set({
                'address': dnspkg.client,
                'id': dnspkg.header.id,
                'qname': dnspkg.q.qname,
                'qtype': dnspkg.q.qtype
            })
            logger.debug(f'receive domain name. dnspkg: {dnspkg}')

            dnspkg_data = await asyncio.create_task(query_create_tasklist(dnspkg))
            if dnspkg_data is not None:
                dnspkg.self_parse(dnspkg_data)
                data = pickle.dumps(dnspkg)
                send_data_amount = ipc_01_mmap.write(data)
                logger.debug(f'send mmap data location: {send_data_amount}, length: {len(data)}')
                send_data_amount_pickle = pickle.dumps(send_data_amount)
                send_data_amount_struct = struct.pack('!H', len(send_data_amount_pickle)) + send_data_amount_pickle
                write(ttl_timeout_response_send_fd, send_data_amount_struct)
        else:
            ipc_01_mmap.mm.close()
            logger.debug('stop server.......')
            break

def start():
    global ipc_01_mmap
    ipc_01_mmap = CircularBuffer(ipc_mmap=share_objects.ipc_01_mmap, ipc_mmap_size=share_objects.ipc_mmap_size)
    logger.debug(f'start ttlout thread server')
    asyncio.run(start_tasks())
