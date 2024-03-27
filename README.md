# Python语言开发DNS服务器

**本项目主要用于学习Python开发，学习Python语法，以及算法**

## 一、实现目标
1. 多组DNS上游服务器
多个上游dns服务器组成查询组，单个分组内的多个上游dns服务器，并发查询，即使其中某个DNS服务器查询失败，也不会影响查询。
2. 缓存加速
缓存采用LRUCache（最近最少使用）策略进行缓存，当再次查询时，可加快dns查询记录, 可持久化cache缓存（使用pickle模块）
3. 域名分流(测试条目数量二十多万，域名列表路径:src/etc/flexidns/list/)
根据域名集合，查询不同上游dns服务器。查询耗时几微妙
4. fallback后备计划(测试IP为中国ipv4、ipv6*地址段*，条目数量一万多，域名列表路径:src/etc/flexidns/list/)
根据IP集合列表，将上游dns服务器返回的IP地址进行匹配，视环境决定使用另一组上游dns服务器查询，通常是加密隧道。查询耗时几微妙
5. 多协议，多端口支持（asyncio实现）
目前完成udp，tcp协议支持，以及每种端口下多个端口同时使用
6. 支持IPv4、IPv6双栈
支持IPv4、IPv6网络，支持查询IPv4、IPv6的记录查询。可禁止IPv6的AAAA记录查询。
7. 可拦截特定类型的查询记录
使用SOA记录来响应特定记录的查询
8. 支持tls, doq协议
9. 使用命令行查询缓存报告
10. 支持idna（国际化dns）

以上为已经实现
---
## 二、未来计划
1. 根据学习Python情况，修改代码使其更规范
2. 支持https协议
3. 根据性能情况，实现正则匹配域名
4. 自动下载更新域名集合列表与IP集合列表
5. 使用tcp进行速度探测（使用linux内核提供链接表进行探测，不使用固定端口探测）
6. 使用命令参数进行在线配置(部分实现)

## 三、使用方法
### 安装
#### 直接启动
1. 克隆或下载
```shell
git clone https://github.com/kulongwangzhi85/flexidns.git
```
2. 安装依赖
```shell
cd flexidns
pip3 install -r requirements.txt
```
3. 启动服务
```shell
touch config_none.toml #空文件
sudo ./src/flexidns start --config ./config_none.toml
或
sudo ./src/flexidns start --config ./src/etc/flexidns/config.toml
```
4. 停止服务
```shell
sudo ./src/flexidns stop
```

**NOTE**: 使用空配置文件时，会使用以下默认值启动服务
##### 默认值
```python
    CACHE_FILE =  f'/var/log/{__package__.lower()}.cache'
    TIME_OUT = 3.0
    SOA_LIST = ['ptr']

    LOG_FILE = f'/var/log/{__package__.lower()}.log'
    LOG_ERROR = f'/var/log/{__package__.lower()}_err.log'
    LOG_LEVEL = 'debug'
    LOG_SIZE = 1
    LOG_COUNTS = 3
    
    TTL_MAX = 7200
    TTL_MIN = 600
    TTL_FAKEIP = 6
    TTL_EXPIRED_REPLY = 1

    DEFAULT_SERVER = {'udp': ':53'}

    DEFAULT_UPSTREAMS = {
        'default': [
            {
                'protocol': 'udp',
                'address': '223.5.5.5',
                'port': 53,
                'ext': None
            }
        ]
    }

    SET_USAGE = [
        {
            'domain-set': {
                'ip-set': {},
                'upstreams': {},
                'blacklist': {}
            }
        },
    ]

    ... ...
```
#### 打包安装
1. 克隆或下载
```shell
git clone https://github.com/kulongwangzhi85/flexidns.git
```
2. 安装依赖
```shell
cd flexidns
pip3 install -r requirements.txt
```
3. build
```shell
python3 -m build -w -o ./ ./
```
> 第一个'./'为打包文件到当前目录。
> 第二个'./'项目根路径（注意不是源码目录）
4. 安装打包好的whl文件
```shell
pip3 install FlexiDNS-1.1.0.dev\*-py3-none-any.whl
```
> 该方法安装的文件，会根据`sys.prefix`的路径进行安装

*sys.prefix*路径
* 如果使用系统软件包管理工具进行安装的python，sys.prefix为`/usr/`
* 使用源码编译的python，则为编译prefix参数指定, 如果未指定。大部分为`/usr/local`
* venv环境`sys.prefix`路径为venv路径（虚拟环境下可不打包），直接启动服务
* 配置文件路径:`<prefix>/etc/flexidns/`
* 主命令文件路径: `<prefix>/bin/`

5. 启动服务
```shell
touch config_none.toml #空配置文件
sudo flexidns start --config ./config_none.toml
或
sudo flexidns start --config ./src/etc/flexidns/config.toml
或
sudo systemctl daemon-reload
sudo systemctl start flexidns.service
```

6. 停止服务
```shell
sudo systemctl stop flexidns.service
或
sudo flexidns stop
```

## 使用
### idna域名使用

> 同普通域名一样配置

![idna](https://github.com/kulongwangzhi85/flexidns/blob/main/docs/images/idna.png)

## 四、详细配置

[详见](https://github.com/kulongwangzhi85/flexidns/blob/main/docs/guide/zh-CN/config.md)

## 五、flexidns命令使用

[详见](https://github.com/kulongwangzhi85/flexidns/blob/main/docs/guide/zh-CN/command.md)

## 六、缓存压测

**不严谨**

### 环境

- 笔记本：LENOVO - ThinkPad T14 Gen 3
- cpu：Intel(R) Core(TM) i5-1240P
- 操作系统：Arch Linux，rolling
- 内核：6.7.6-arch1-1
- 软件dnsperf：Version 2.11.2
- dnsperf与dns服务器在同一台笔记本

> **服务器模式为单进程asyncio**
> **进程作用：1进程dns客户端与日志线程，2进程dns服务器端**


1. 日志级别DEBUG

![image01](https://github.com/kulongwangzhi85/flexidns/blob/main/docs/images/dnsperf01.png)

> 正在压测时的cpu使用率

![image02](https://github.com/kulongwangzhi85/flexidns/blob/main/docs/images/dnsperf02.png)

2. 日志级别CRITICAL

![image04](https://github.com/kulongwangzhi85/flexidns/blob/main/docs/images/dnsperf04_disablelog.png)

> 正在压测时的cpu使用率

![image03](https://github.com/kulongwangzhi85/flexidns/blob/main/docs/images/dnsperf03_disablelog.png)

![image05](https://github.com/kulongwangzhi85/flexidns/blob/main/docs/images/dnsperf05_disablelog.png)

3. 使用uvloop

![image05](https://github.com/kulongwangzhi85/flexidns/blob/main/docs/images/dnsperf06_disablelog_uvloop.png)

*Python日志对性能的影响非常大*

## 六、许可协议
FlexiDNS 遵循GPL v3.0协议
