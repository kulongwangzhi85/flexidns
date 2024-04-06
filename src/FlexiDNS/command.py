
# coding: utf-8

"""建立socket，用于命令行方式执行cache相关操作, 例如显示，新增，删除"""

import base64
import datetime
import mmap
import os
import pickle
from pickle import UnpicklingError
import socket
from sys import stderr
from signal import signal, SIGPIPE, SIG_DFL

from prettytable import PrettyTable
from dnslib import DNSLabel, DNSLabelError, CLASS, QTYPE

from .tomlconfigure import share_objects

signal(SIGPIPE, SIG_DFL)


class CacheOperate:
    def __init__(self):
        if os.path.exists(share_objects.SOCKFILE):
            self.socket_file = share_objects.SOCKFILE
        else:
            outerr_message = "Server is not running, please use command 'systemctl start flexidns' or 'flexidns start --config /path/etc/flexidns/config.toml'"
            print(outerr_message, flush=True, file=stderr)
            os._exit(1)

    def data_recv(self, message):
        client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client_socket.setblocking(True)
        try:
            # 连接到服务器
            client_socket.connect(self.socket_file)

            # 发送消息给服务器
            client_socket.sendall(message)

            # 接收服务器的响应
            data = pickle.loads(client_socket.recv(1024))

        except (socket.error, EOFError) as e:
            print("通信错误:", e)
            os._exit(1)
        finally:
            client_socket.close()

        if data.get('data_length') > 0:
            mmap_file = pickle.loads(base64.b64decode(data.get('data')))
            fd = os.open(mmap_file, os.O_RDONLY)
            mm = mmap.mmap(fd, data.get('data_length'), prot=mmap.PROT_READ)
            os.close(fd)

            data.update({'data': mm})

        return data

    def rules(self, args):
        # 用于rules命令查询
        if qnames := args.get('rules').get('delete'):
            __qnames = []
            for qname in qnames:
                try:
                    __qnames.append(str(DNSLabel(qname)))
                except (DNSLabelError, UnicodeError) as e:
                    print(f'invalid domain name: {qname}', flush=True, file=stderr)
                    os._exit(1)

            qnames.clear()
            qnames.extend(__qnames)
        message = pickle.dumps(args)
        recv_data = self.data_recv(message)
        length, mm = recv_data.get('data_length'), recv_data.get('data')
        mmdata = mm.read(length) if length > 0 else recv_data.get('data')
        if mmdata:
            data = pickle.loads(mmdata) if isinstance(mmdata, bytes) else mmdata
            match recv_data['argparse']:
                case 'show':
                    # 显示规则名
                    print(f'rules: {data}')

                case 'delete':
                    # 删除规则
                    x = PrettyTable()
                    x.field_names = ['query name', 'befor rule', 'after rule']
                    for i in data:
                        if i is not None:
                            for domanname, respones_data in i.items():
                                x.add_row(
                                    [
                                        domanname,
                                        respones_data.get('befor'),
                                        respones_data.get('after')
                                    ])
                            print(x)
                        else:
                            print(f'rule {data["delete"]} not found, no action performed')

                case 'count':
                    # 查看规则数量
                    print(f'rule counts: {data}')

                case 'rule':
                    # 用于修改规则

                    x = PrettyTable()
                    x.field_names = ['query name', 'rule']
                    for i in data:
                        if i is not None:
                            x.add_row(i)
                    print(x)

                case 'name':
                    # 查询指定域名规则

                    x = PrettyTable()
                    x.field_names = ['query name', 'rule']
                    for i in data:
                        if i is not None:
                            x.add_row(i)
                    print(x)

        else:
            print('get data error')

    def cache(self, args):
        if qnames := args.get('cache').get('qname'):
            __qnames = []
            for qname in qnames:
                try:
                    __qnames.append(str(DNSLabel(qname)))
                except (DNSLabelError, UnicodeError) as e:
                    print(f'invalid domain name: {qname}', flush=True, file=stderr)
                    os._exit(1)
            qnames.clear()
            qnames.extend(__qnames)
        message = pickle.dumps(args)
        recv_data = self.data_recv(message)
        mm = recv_data.get('data')

        mmdata_bytes = CacheOperate.unloads(mm)
        for i in mmdata_bytes:
            if isinstance(i, list):
                for x in i:
                    if type(x) == int:
                        # 缓存中有保存rcode记录
                        continue
                    for xx in x:
                        print(
                            f'{xx.rname.idna():^30} {xx.ttl:^10} {CLASS.get(xx.rclass)} {QTYPE.get(xx.rtype):^10} {xx.rdata}')
            if isinstance(i, dict):
                for x in i.values():
                    for s in x.values():

                        if isinstance(s, int):
                            # 缓存中有保存rcode记录
                            continue
                        for xx in s:
                            print(
                                f'{xx.rname.idna():^30} {xx.ttl:^10} {CLASS.get(xx.rclass)} {QTYPE.get(xx.rtype):^10} {xx.rdata}')

    @staticmethod
    def unloads(fd):
        while True:
            try:
                yield pickle.load(fd)
            except EOFError:
                break

    def history(self, args):
        # 用于history命令查询

        message = pickle.dumps(args)
        recv_data = self.data_recv(message)
        mm = recv_data.get('data')

        try:
            mmdata_bytes = pickle.loads(mm)
        except UnpicklingError as e:
            mmdata_bytes = []
            print('error:', e, file=stderr, flush=True)

        # 显示客户端查询历史记录
        x = PrettyTable()
        x.field_names = ['time', 'client', 'domain name']
        for i in mmdata_bytes:
            if i is not None:
                x.add_row(
                    (
                        datetime.datetime.fromtimestamp(i[0]).strftime('%Y-%m-%d %H:%M:%S.%f'),
                        i[1],
                        i[2]
                    )
                )
        print(x)

    def _verify_args(self, args):
        error_string = "~!@#$%^&:;()_+<>,[]\\/{|}"
        if args:
            for arg in args.values():
                for i in arg.values():
                    if isinstance(i, list):
                        for user_data in i:
                            for err_str in error_string:
                                if err_str in user_data:
                                    return False
                    return True
        else:
            return False
