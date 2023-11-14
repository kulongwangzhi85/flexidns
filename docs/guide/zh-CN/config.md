
# flexidns配置

## 配置文件格式

flexidns使用toml格式

[tomla语法](https://toml.io/cn/v1.0.0)

## config.toml配置文件结构

```toml
[globals]
[edns0]
[server]
[blacklist]
[upstreams]
[fallback]
[logs]
[static]
[ip-set]
[domain-set]
[[set-usage]]
```

## [globals]段配置

globals配置如下:

* `basedir = "/<sys.prefix>/path/etc/flexidns/list"`

domain-set与ip-set集合列表的目录路径, 简化domain-set与ip-set集合列表只需要填写文件名

* `timeout = 3.0`

flexidns向上游dns服务器发起查询的超时时间

* `expired_reply_ttl = 1`

当dns缓存过期时，响应客户端ttl时间。并同时向上游再一次发起查询

* `ttl_max = 7600`

修改上游返回dns报文ttl时间大于该值

* `ttl_min = 600`

修改上游返回dns报文ttl时间小于该值

* `fakeip_ttl = 6`

修改flexidns后端提供fakeip的ttl时间

*NOTE*:需要后端有fakeip服务器，类似v2ray等

* `soa = ["ptr"]`

阻止soa列表中的查询记录，返回空值。
`soa = ["ptr", "aaaa"]`, 阻止反向解析与ipv6地址解析

* `cache_persist = true 或 false`

是否缓存持久化dns缓存, 开启后。再下一次服务启动时加载文件到缓存，停止服务时保存到指定文件

* `cache_file = "/path/flexidns.cache"

缓存持久化保存路径与文件名

* `tls_cert = "/sys.prefix/etc/flexidns/ssl/xxx.xx.cer"`

* `tls_cert_key = "/sys.prefix/etc/flexidns/ssl/xxx.xx.key"`

* `tls_cert_ca = "/sys.prefix/etc/flexidns/ssl/ca.cer"`

tls证书路径，用于flexidnsn提供dns over tls服务

## [logs]段配置

flexidns日志配置

* `logfile = "/path/flexidns.log"`

日志存放的文件路径

> **NOTE**:路径必须存在, 日志文件自动创建

* `logerror = "/path/flexidns_err.log"`

错误日志存放的文件路径

> **NOTE**:路径必须存在, 日志文件自动创建。该文件只保存错误日志。logfile也会同时保存错误

* `loglevel = "debug"`

日志级别, 可使用字符串: 'debug', 'info', 'warning', 'error', 'critical'

* `logcounts = 3`

日志轮滚后保持的日志文件数

* `logsize = 3`

每个日志文件大小，单位：m

## [edns0]段配置

* `ipv4_address = "xxx.xxx.xxx.xxx"`

一个合法的公网ipv4地址, 用于向支持edns0功能的DNS提供商发起查询

**NOTE**:不可填写私有IP地址！例如`192.168.1.1`

*如果你的网络出口没有公网IP地址。可使用搜索工具，搜索<IP地址查询>获得你最外层出口的公网IP地址*

* `ipv6_address = "xxxx:xxxx:xxx:xxxx::"`

一个合法的公网ipv6地址, 用于向支持edns0功能的DNS提供商发起查询

> 可只填写IPv6网络地址

**NOTE**:不可填写私有IP地址！

## [server]段配置

flexidns提供服务的配置段

* `udp = ":53"`

* `tcp = "[::]:53, 0.0.0.0:53"`

* `dot = ":853"`

**NOTE**: 目前只实现以上三种

## [static]段配置

`[static]静态域名映射`

配置文件格式采用与linux系统下的/etc/hosts文件格式相同，
一行一个规则，一个域名可配置多个ipv4与ipv6地址
\#开头为注释行，该行的设置将不生效

### 格式

`IP DOMAINNAME`

#### 案例

```shell
192.168.1.1 gateway.example.com
fd11:88::1 gateway.example.com
```

### RCode - dns响应代码

| RCode | 描述 |
| --- | --- |
| success | 无错误 |
| format_error | 请求格式错误 |
| server_failure | 服务器出错 |
| name_error | 域名不存在 |
| not_implemented | 功能未实现 |
| refused | 请求被拒绝 |
