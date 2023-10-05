from pydns.Lib import thpool_callback, async_th, async_mp
from concurrent.futures import ThreadPoolExecutor
from time import perf_counter
import os, dnslib, socket, pickle, logging

logger = logging.getLogger(__package__)
g_vars = None
queryput = None
queryget = None
speedqueue = None
ipsearch = None
searchip = None
pickcache = {}
cachelist = set()
speedfailcache = set()  # 缓存测速失败的域名, todo NOTE 注意list列表会增大

thpool_speed = ThreadPoolExecutor(max_workers=10, thread_name_prefix='speed_')

# @async_th
# def speed_queue():
#     logger.debug('back_process pid {}'.format(os.getpid()))
#     while True:
#         speeddata = speedqueue.get()
#         thpool_speed.submit(speed_tcp, speeddata).add_done_callback(thpool_callback)

# def speed_tcp(speeddata: list):
#     # speeddata:
#     # [(qname, rname, rtype, rdata),...]
#     flags = True
#     tcp_speed_list = []
#     tmp_list = []

#     for i in speeddata:
#         if i[0] in cachelist:
#             # 跳过之前测试失败的域名，无需往下执行
#             logger.debug(f'check {i[0]} is in cachelist, so skip speed test')
#             break
#         if i[2] == dnslib.QTYPE.AAAA or i[2] == dnslib.QTYPE.A:
#             ipaddr = str(i[3])
#             try:
#                 t_start = perf_counter()
#                 s = socket.create_connection((ipaddr, g_vars.speedtcpport), timeout=0.6)
#             except (TimeoutError,ConnectionRefusedError, OSError) as e:
#                 flags = False
#             else:
#                 s.shutdown(2)
#                 s.close()
#             finally:
#                 if flags:
#                     usetime = perf_counter() - t_start
#                     # Threshold 阀值
#                     # todo: NOTE 未来考虑使用阀值控制解析ip地址的数量,也就是大于多少时间丢弃，
#                     # 经过测速的ip地址，未超过阀值的地址则全部返回并缓存
#                     if not ipsearch.checkip(ipaddr):
#                         # todo: NOTE 未来考虑在这里实现非cn地址，超过阀值，调用防火墙规则集nftset/ipset，或跳转到其它rulestabs规则
#                         logger.debug(f'non cn ip {ipaddr} address range, speed is {usetime}')
#                     tcp_speed_list.append((i[0], i[1], i[2], i[3], usetime))
#                 else:
#                     cachelist.add(i[0])
#                     logger.warning(f'speed test fail: {ipaddr}, domain name write in cachelist next skip test')
#         else:
#             tmp_list.append(i) # 接收非A记录与AAAA记录

#     if len(tcp_speed_list) > 0:
#         # tcp测速后
#         tmp_list2 = []
#         for i in tcp_speed_list:
#             if i[4] <= g_vars.query_threshold:
#                 tmp_list2.append(i)
#                 # todo: NOTE 后期实现非国内IP地址动作
#         if len(tmp_list2) == 0:
#             tmp_a = sorted(tcp_speed_list, key=lambda sortfunc: sortfunc[4])
#             # 排序为了让最低延时IP排在前面
#         else:
#             tmp_a = sorted(tmp_list2, key=lambda sortfunc: sortfunc[4])
#         tmp_list.extend(tmp_a)
#         logger.debug(f'check speed result: {tmp_a}')
#         for i in tmp_a:
#             match i[2]:
#                 case dnslib.QTYPE.A:
#                     cache.updaterdata(tmp_list, qname=i[0])
#                 case dnslib.QTYPE.AAAA:
#                     cacheaaaa.updaterdata(tmp_list, qname=i[0])
#     else:
#         # 未经过tcp测速
#         for i in speeddata:
#             match i[2]:
#                 case dnslib.QTYPE.A:
#                     cache.updaterdata(speeddata, qname=i[0])
#                 case dnslib.QTYPE.AAAA:
#                     cacheaaaa.updaterdata(speeddata, qname=i[0])

# @async_mp
# def speed_start():
#     _init()
#     while True:
#         token = None
#         query = queryput.get()
#         logger.debug(f'{__name__} recv query queue {query}')
#         if 'token' in query:
#             token = query.pop('token')
#         tmp_query = query.popitem()