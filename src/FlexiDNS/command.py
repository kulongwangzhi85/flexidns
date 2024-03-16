
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

from .tomlconfigure import configs
from .dnscache import lrucacheout

signal(SIGPIPE, SIG_DFL)


class CacheOperate:
    def __init__(self):
        if os.path.exists(configs.sockfile):
            self.socket_file = configs.sockfile
        else:
            outerr_message = "Server is not running, please use command 'systemctl start flexidns' or 'flexidns start --config /path/etc/flexidns/config.toml'"
            print(outerr_message, flush=True, file=stderr)
            os._exit(1)

    def __data_recv(self, message):
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

        if self._verify_args(args) is False:
            print("invalid domain name!", flush=True, file=stderr)
            os._exit(1)
        message = pickle.dumps(args)
        recv_data = self.__data_recv(message)
        length, mm = recv_data.get('data_length'), recv_data.get('data')
        mmdata = mm.read(length) if length > 0 else recv_data.get('data')
        if mmdata:
            data = pickle.loads(base64.b64decode(mmdata)) if isinstance(mmdata, bytes) else mmdata
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
        message = pickle.dumps(args)
        recv_data = self.__data_recv(message)
        length, mm = recv_data.get('data_length'), recv_data.get('data')
        if length > 0:
            mmdata = mm.read(length)
        else:
            mmdata = mm

        try:
            mmdata_bytes = pickle.loads(base64.b64decode(mmdata))
        except UnpicklingError as e:
            mmdata = b''
            print('error:', e, file=stderr, flush=True)
        if mmdata_bytes is True:
            return

        if type(mmdata_bytes) is set:
            for i in mmdata_bytes:
                print(i)
        elif type(mmdata_bytes) is lrucacheout:
            for data in mmdata_bytes.search_cache.values():
                for i in data:
                    for s in i:
                        for x in s.values():
                            if isinstance(x, int):
                                continue
                            if len(x) > 0:
                                for xx in x:
                                    print(xx)
                            else:
                                continue

    def history(self, args):
        # 用于history命令查询

        message = pickle.dumps(args)
        recv_data = self.__data_recv(message)
        length, mm = recv_data.get('data_length'), recv_data.get('data')
        mmdata = mm.read(length)

        try:
            mmdata_bytes = pickle.loads(base64.b64decode(mmdata))
        except UnpicklingError as e:
            mmdata = b''
            print('error:', e, file=stderr, flush=True)
        if mmdata_bytes is True:
            return

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
