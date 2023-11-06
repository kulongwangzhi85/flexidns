
# coding: utf-8

"""
用于ttl过期时，从该进程发起查询。独立于dnsserver进程
NOTE：如果开启缓存，再次重启服务。由于未缓存ttl，因此重启后的ttl都是过期的，也就是重启后，缓存域名都会经过该进程发起请求，来更新缓存
"""

import asyncio
import contextvars
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

contextvars_rules = contextvars.ContextVar('dnsrules', default=None)


async def start_tasks():
    from .dnsupstream import query_create_tasklist

    ttl_timeout_recv = share_objects.ttl_timeout_recv
    ttl_timeout_response_send_fd = share_objects.ttl_timeout_response_send
    
    ipc_mmap = CircularBuffer(ipc_mmap=share_objects.ipc_mmap, ipc_mmap_size=share_objects.ipc_mmap_size)

    dnspkg_obj = namedtuple('dnspkg', [
        'id',
        'client',
        'qname',
        'qtype',
        'edns0',
        'non_edns0',
        'configs',
        'upserver',
        'rules',
        'data_amount'
    ])

    while True:
        dict_data = ttl_timeout_recv.recv()
        if dict_data:
            contextvars_rules.set(dict_data.get('rules'))
            _dnspkg_ttl = dnspkg_obj(**dict_data)
            data_amount = _dnspkg_ttl.data_amount

            logger.debug(f'data_amount: {data_amount}')
            dns_packaged = ipc_mmap.read(data_amount)

            dns_prefix = struct.unpack('!HH', dns_packaged[:4])
            _non_edns0=dns_packaged[4:dns_prefix[0]+4]
            _edns0=dns_packaged[4+dns_prefix[0]:]

            logger.debug(f'dns_packaged: {dns_packaged}')

            dnspkg_ttl = _dnspkg_ttl._replace(non_edns0=_non_edns0, edns0=_edns0)

            logger.debug(f'non_eddns0: {dnspkg_ttl.non_edns0}, edns0: {dnspkg_ttl.edns0}')

            contextvars_dnsinfo.set({
                'address': dnspkg_ttl.client,
                'id': dnspkg_ttl.id,
                'qname': dnspkg_ttl.qname,
                'qtype': dnspkg_ttl.qtype
            })
            logger.debug(f'recviced domain name')

            dnspkg_data = await asyncio.create_task(query_create_tasklist(dnspkg_ttl))
            if dnspkg_data is not None:
                data = pickle.dumps((dnspkg_data, contextvars_rules.get()))
                data_amount = ipc_01_mmap.write(data)
                data_amount_pickle = pickle.dumps(data_amount)
                data_amount_struct = struct.pack('!H', len(data_amount_pickle)) + data_amount_pickle
                write(ttl_timeout_response_send_fd, data_amount_struct)
        else:
            ipc_01_mmap.mm.close()
            logger.debug('stop server.......')
            break

def start():
    global ipc_01_mmap
    ipc_01_mmap = CircularBuffer(ipc_mmap=share_objects.ipc_01_mmap, ipc_mmap_size=share_objects.ipc_mmap_size)
    logger.debug(f'start ttlout dnsserver')
    asyncio.run(start_tasks())
