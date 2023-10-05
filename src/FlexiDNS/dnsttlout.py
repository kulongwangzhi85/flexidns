
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

logger = getLogger(__name__)
contextvars_dnsinfo = share_objects.contextvars_dnsinfo
logger = dnsidAdapter(logger, {'dnsinfo': contextvars_dnsinfo})

contextvars_rules = contextvars.ContextVar('dnsrules', default=None)


async def start_tasks():
    from .dnsupstream import query_create_tasklist
    ttl_timeout_recv = share_objects.ttl_timeout_recv
    ttl_timeout_event = share_objects.ttl_timeout_event
    ttl_timeout_response_send_fd = share_objects.ttl_timeout_response_send

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
    ])

    while True:
        dict_data = ttl_timeout_recv.recv()
        if dict_data:
            contextvars_rules.set(dict_data.get('rules'))
            dnspkg_ttl = dnspkg_obj(**dict_data)
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
                data_length = len(data)
                data_with_data_length = struct.pack('!H', data_length) + data
                write(ttl_timeout_response_send_fd, data_with_data_length)

        if ttl_timeout_event.is_set():
            # 退出循环
            break


def start():
    logger.debug(f'start ttlout dnsserver')
    asyncio.run(start_tasks())
