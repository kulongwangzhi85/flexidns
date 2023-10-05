
# coding: utf-8

import sys
import os
import logging
import pickle

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s %(name)s %(levelname)s %(lineno)s %(message)s",
                    datefmt='%Y-%m-%d  %H:%M:%S %a'  # 注意月份和天数不要搞乱了，这里的格式化符与time模块相同
                    )
sys.path.append(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))) + '/src/')
from FlexiDNS.tomlconfigure import loader_config, share_objects, configs
loader_config(
    '/home/guocl/Python/proj003/src/etc/flexidns/config_devel.toml')
# '/home/guocl/Python/proj003/src/etc/pydns/config.toml')
# print(configs.set_usage[0].get('domain-set').get('ip-set'))
# print(configs.ipset)
print(configs.mmapfile)


# for i in configs.__dict__:
#     print(i, configs.__dict__.get(i))
# set_upstreams = set()
# dnsserver_name = set()

# upstreams_name = configs.set_usage[0].get('domain-set').get('upstreams').keys()

# for i in upstreams_name:
#     set_upstreams.add(i)

# for i in configs.dnsservers.keys():
#     dnsserver_name.add(i)

# dnsserver_name.difference_update(set_upstreams)

# for i in dnsserver_name:
#     default_upstreams = (configs.dnsservers.get(i))

# print(configs.default_upstream_rule, configs.default_upstream_server)
