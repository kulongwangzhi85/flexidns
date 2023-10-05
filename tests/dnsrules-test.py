import sys
import os
import logging
import time

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s %(name)s %(levelname)s %(lineno)s %(message)s",
                    datefmt='%Y-%m-%d  %H:%M:%S %a'  # 注意月份和天数不要搞乱了，这里的格式化符与time模块相同
                    )
sys.path.append(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))) + '/src/')
from pydns.tomlconfigure import loader_config
loader_config('/home/guocl/Python/proj002/src/etc/pydns/config_devel.toml')
from pydns.tomlconfigure import configs
from pydns.dnsrules_new import module_init
module_init()
from pydns.dnsrules_new import rulesearch, iprepostitory
# print(IPRepostitory.ipv4_repostitorys)
# start_time = time.perf_counter()
iprepostitory.search('2408:8248:480:778c:69f9:ad99:d4c:37f4', repositorie='cn')
start_time = time.perf_counter()
status = iprepostitory.search('157.148.69.80', repositorie='cn')
# status = iprepostitory.search('192.168.2.11', rulename='cn')

print(f'end time: {time.perf_counter() - start_time}, status: {status}')


# print(rulesearch.search('www.baidu.com', repositorie='ip-sets-checkpoint'))
print(rulesearch.search('www.baidu.com', repositorie='upstreams-checkpoint'))
# print(rulesearch.repositories.get('ip-sets-checkpoint'))
# rulesearch.modify('*.love67.net', rule='proxy')
# logger.debug(rulesearch.search('tools.l.google.com', rulename='direct'))
# print(configs.domainname_set)
# checklist = {'cn', 'proxy', 'static', 'ad'}


# def main():

#     result = set()
#     for i in map(lambda x: rulesearch.search(
#             'www.asdfkajsdfkjwejrq.com', rulename=x), checklist):
#         if i is not None:
#             result.add(i)

#     print(result, len(result))

#     return next(filter(None, result)) if len(result) > 0 else configs.default_upstream_rule
#     # yield configs.default_upstream_rule


# m = main()
# print(m)


# "ipv4.icanhazip.com",
# "ns1.digitalocean.com",
