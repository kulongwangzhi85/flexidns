
# coding: utf-8

"""建立socket，用于命令行方式执行cache相关操作, 例如显示，新增，删除"""

import base64
import mmap
import os
import pickle
from pickle import UnpicklingError
import socket
import struct
from sys import stderr
from signal import signal, SIGPIPE, SIG_DFL

from prettytable import PrettyTable

from .tomlconfigure import configs

signal(SIGPIPE, SIG_DFL)


class CacheOperate:
    def __init__(self):
        from os import path, _exit
        if path.exists(configs.sockfile):
            self.socket_file = configs.sockfile
        else:
            outerr_message = "Server is not running, please use command 'systemctl start flexidns' or 'flexidns start --config /path/etc/flexidns/config.toml'"
            print(outerr_message, flush=True, file=stderr)
            _exit(1)

        self.mmap_file = configs.mmapfile

    def rules(self, args):
        """
        defaults:
        name=query_name -> data type: list,
        rules=None -> data type: str,
        count=False, 
        show=False, 
        delete=None -> data type: list

        args = {
            "rules": {
                "name": name,
                "rule": rule,
                "count": count,
                "show": show,
                "delete": delete
            }
        }
        """
        # 用于rules命令查询
        message_data = pickle.dumps(args)
        client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client_socket.setblocking(True)
        try:
            # 连接到服务器
            client_socket.connect(self.socket_file)
            client_socket.sendall(message_data)

            # 接收服务器的响应
            bytes_data = client_socket.recv(1024)
            if bytes_data:
                data = pickle.loads(bytes_data)
                match data['cmd']:
                    case'show':
                        # 显示规则名
                        print(f'rules: {data["show"]}')

                    case 'delete':
                        # 删除规则
                        x = PrettyTable()
                        x.field_names = ['query name',
                                         'befor rule', 'after rule']
                        for i in data['data']:
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
                        print(f'rule counts: {data["count"]}')

                    case 'rule':
                        # 用于修改规则
                        struct_length_fmt = f'!{len(data["rule"])//2}H'
                        data_length = struct.unpack(
                            struct_length_fmt, data['rule'])

                        fd = os.open(self.mmap_file, os.O_RDONLY)
                        mm = mmap.mmap(fd, sum(data_length),
                                       prot=mmap.PROT_READ)
                        mmdata = mm.readline()
                        mmdata_bytes = pickle.loads(base64.b64decode(mmdata))
                        x = PrettyTable()
                        x.field_names = ['query name', 'rule']
                        for i in mmdata_bytes:
                            if i is not None:
                                x.add_row(i)
                        print(x)

                    case 'name':
                        # 查询指定域名规则
                        struct_length_fmt = f'!{len(data["name"])//2}H'
                        data_length = struct.unpack(
                            struct_length_fmt, data['name'])

                        fd = os.open(self.mmap_file, os.O_RDONLY)
                        mm = mmap.mmap(fd, sum(data_length),
                                       prot=mmap.PROT_READ)
                        mmdata = mm.readline()
                        mmdata_bytes = pickle.loads(base64.b64decode(mmdata))
                        x = PrettyTable()
                        x.field_names = ['query name', 'rule']
                        for i in mmdata_bytes:
                            if i is not None:
                                x.add_row(i)
                        print(x)

            else:
                print('get data error')

        except socket.error as e:
            print("通信错误:", e)
        finally:
            # 关闭套接字
            client_socket.close()

    def cache(self, args):
        message_data = pickle.dumps(args)
        client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client_socket.setblocking(True)
        try:
            # 连接到服务器
            client_socket.connect(self.socket_file)

            # 发送消息给服务器
            client_socket.sendall(message_data)

            # 接收服务器的响应
            struct_data_length = client_socket.recv(1024)
            struct_length_fmt = f'!{len(struct_data_length)//2}H'
            data_length = struct.unpack(struct_length_fmt, struct_data_length)

            fd = os.open(self.mmap_file, os.O_RDONLY)
            mm = mmap.mmap(fd, sum(data_length), prot=mmap.PROT_READ)
            mmdata = mm.readline()
            try:
                mmdata_bytes = pickle.loads(base64.b64decode(mmdata))
            except UnpicklingError as e:
                mmdata = b''
                print('error:', e, file=stderr, flush=True)
            if mmdata_bytes is True:
                return 

            if len(mmdata) > 0 or len(mmdata) == data_length:
                for i in mmdata_bytes:
                    print(i)
            else:
                print(
                    f'mmdata length: {len(mmdata)}, struct length: {data_length}, struct_data_length: {struct_data_length}')
                print(f'struct length: {sum(data_length)}')

        except socket.error as e:
            print("通信错误:", e)
        finally:
            # 关闭套接字
            client_socket.close()

    def _format(self, b64_data):
        import base64
        data_table = PrettyTable(
            ['search domain name', 'qtype', 'response data'])
        data = base64.b64decode(b64_data)
        raw_data = eval(data)
        if raw_data:
            for i in raw_data:
                raw_data_in = i.split()
                del (raw_data_in[1], raw_data_in[1])
                data_table.add_row(
                    [raw_data_in[0], raw_data_in[1], raw_data_in[2]])
            print(data_table)
        else:
            print(data_table)
        return
