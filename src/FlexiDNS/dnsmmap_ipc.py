
# coding: utf-8

"""
环形缓存
用于两个进程间，单向传递数据
"""

from array import array
import mmap
import typing as t
from logging import getLogger

logger = getLogger(__name__)

HEAD: t.TypeAlias = int
TAIL: t.TypeAlias = tuple[int, int]
DATA_LOCATION: t.TypeAlias = list[HEAD, TAIL]

class CircularBuffer:
    def __init__(self, ipc_mmap:mmap, ipc_mmap_size: int):
        """
        环形缓冲区：
        参数:
            ipc_mmap: 匿名mmap对象
            ipc_mmap_size: int, 环形缓冲区大小, 该大小必须与mmap设置大小一致
        """
        self.mm:t.BinaryIO[t.IO(bytes)] = ipc_mmap
        self.size:int = ipc_mmap_size
        self.locations = self.__data_location()
        next(self.locations)

    def __data_location(self) -> DATA_LOCATION:
        """
        循环算法
        作用： 固定mmap长度后，从data长度中算出数据的起始位置和结束位置
        返回值：
            type：list
            结构：list[int, list[int, int]]
            描述：
                [起始位置, [<'mmap size' - 起始位置 or 0>, 结束位置]]
                NOTE: 当结束位置超过mmap size时，内嵌列表的起始位置为：mmap长度 - 起始位置
        案例：
                pool = pooling(2000)
                next(pool)
                print(pool.send(1000)) # [0, (0, 1000)]
                print(pool.send(200))  # [1000, (0, 200)]
                print(pool.send(1000)) # [1200, (800, 200)]
                print(pool.send(500))  # [200, (0, 500)]
                print(pool.send(500))  # [700, (0, 500)]
                print(pool.send(500))  # [1200, (0, 500)]
                print(pool.send(500))  # [1700, (300, 200)]
                print(pool.send(500))  # [200, (0, 500)]
                print(pool.send(500))  # [700, (0, 500)]
            or:
                pool = pooling(2000)
                next(pool)

                for _ in range(100000):
                    x = random.randint(10, 1000)
                    print(x, pool.send((x)))
        """
        is_full:bool = False
        start_location: HEAD = 0
        end_location_head = 0
        end_location_end = 0
        data_arrary = array('I', [start_location, end_location_head, end_location_end])
        """
        注意array的数据类型范围必须大于ipc_mmap_size：
        'h': short int: -32768 ~ 32767
        'H': unsigned short int: 0 ~ 65535
        'i': int: -2147483648 ~ 2147483647
        'I': unsigned int: 0 ~ 4294967295
        'l': long int: -9223372036854775808 ~ 9223372036854775807
        'L': unsigned long int: 0 ~ 18446744073709551615
        """
        size:int = self.size

        while True:
            data_arrary[0] = start_location
            data_arrary[1] = end_location_head
            data_arrary[2] = end_location_end
            datasize: int = yield data_arrary
            if datasize > size:
                logger.error(f'data size exceed mmap size, data size: {datasize}')
                continue

            if is_full:
                start_location = end_location_end
                end_location_head = 0
                is_full = False
            else:
                start_location = (start_location + end_location_end) % size

            end_location_end = datasize

            if (current_datasize := start_location + (end_location_head + end_location_end)) > size:
                end_location_head = size - start_location
                end_location_end = abs(size - current_datasize)
                is_full = True

    def read(self, locations: DATA_LOCATION) -> bytes:
        self.mm.seek(locations[0])
        if locations[1] > 0:
            tmp_data = bytearray()
            tmp_data.extend(self.mm.read(locations[1]))
            self.mm.seek(0)
            tmp_data.extend(self.mm.read(locations[2]))
            return tmp_data
        else:
            return self.mm.read(locations[2])

    def write(self, data: bytes) -> DATA_LOCATION:

        data_amount = self.locations.send(datasize:=len(data))
        self.mm.seek(data_amount[0])

        if data_amount[1] > 0:
            memv_data = memoryview(data)
            self.mm.write(memv_data[0:data_amount[1]])
            self.mm.seek(0)
            self.mm.write(memv_data[data_amount[1]:])
        else:
            self.mm.write(data)

        return data_amount

if __name__ == '__main__':
    import os
    os._exit(0)
