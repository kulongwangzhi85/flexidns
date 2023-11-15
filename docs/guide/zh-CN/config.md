
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

* `"list" = "hosts"`

静态域名与ip地址映射文件，如果`[globals]`配置有`basedir`,则可以只填写文件名。否则必须填写绝对路径

* `"domainname_v4" = { "new.example.org" = "192.168.3.3", "cloud.example.org" = "192.168.3.30" }`

在配置文件中，配置域名与ipv4地址映射。

* `"domainname_v6" = { "cloud.example.org" = "2408:8248:480:31b8::1" }`

在配置文件中，配置域名与ipv6地址映射。

### hosts文件格式

`IP DOMAINNAME`

配置文件格式采用与linux系统下的/etc/hosts文件格式相同，一行一个规则，一个域名可配置多个ipv4与ipv6地址
\#开头为注释行，该行的设置将不生效

#### 案例

```shell
192.168.1.1 gateway.example.com
fd11:88::1 gateway.example.com
```

## [upstreams]段配置

配置flexidns的上游dns服务器地址与协议

```toml
cn = [
    { protocol = "udp", address = "223.5.5.5", port = 53, ext = "edns0" },
    { protocol = "tcp", address = "2400:3200::1", port = 53, ext = "edns0" },
    { protocol = "udp", address = "58.22.96.66", port = 53 },
]
```

### 格式

```shell
分组名 = [{dns服务器}, ...]
```

分组名: 自定义字符串
服务器列表：使用列表

#### dns服务器列表格式

`{ protocol = "udp", address= "223.5.5.5", port = 53, ext = "edns0" 或 无ext字段 }`

* protocol: > "udp", "tcp", "doq", "dot"
* address： 上游服务器ipv4或ipv6地址
* port: 上哟服务器提供的端口
* ext: 扩展，目前只有"edns0" 与 "fakeip

**NOTE:"edns0"功能需要配置["edns0"]段配置, "fakeip"功能需要flexidns后端g提供fakeip地址，e这里填写的ip地址只是作为d判断依据**

### 案例

```toml
cn = [
    { protocol = "udp", address = "223.5.5.5", port = 53, ext = "edns0" },
    { protocol = "tcp", address = "2400:3200::1", port = 53, ext = "edns0" },
    { protocol = "udp", address = "114.114.114.114", port = 53 },
]

proxy = [
    { protocol = "doq", address = "94.140.14.141", port = 853, ext = "edns0" },
    { protocol = "dot", address = "1.1.1.1", port = 853, ext = "edns0" },
    { protocol = "udp", address = "127.0.0.1", port = 15656, ext = "fakeip", fakeip = "198.18.0.0/15,fc00::/64" },
]
```

## [ip-set]段配置

ip地址集合配置

作用：ip集合用于上游DNS服务器返回解析后，进行判断该ip是否属于某个集合。
主要应对域名未匹配，但是解析后ip命中匹配。

主要使用场景： 上游DNS需要fakeip，主要应对类似cloudflare这样CDN。多个域名使用一个ip。

> **NOTE: ip-set代码未全部实现，主要部分的IP匹配已完成,目前只是在日志中打印出结果**

指定集合文件路径

```shell
cloudflare = { "list" = ["cloudflare.txt"], "ip" = [] }
telegram = { "list" = "telegram.txt" }
cn = { "list" = ["cn-all.txt"], "ip" = [] }
```

### 格式

* `set-name = { "list" = [set-file, ...], "ip" = ["ip address", ...] }`

> **NOTE: {}内 ’=’左边的"list"与“ip”不可变**

集合名：自定义字符串

## [blacklist]段配置

黑名单列表配置

* `domain-set = ["ad"]`

黑名单域名集合名

* `rcode = "success"`

响应报文rcode码，提供给客户端不同的响应

### RCode - dns响应代码

| RCode | 描述 |
| --- | --- |
| success | 无错误 |
| format_error | 请求格式错误 |
| server_failure | 服务器出错 |
| name_error | 域名不存在 |
| not_implemented | 功能未实现 |
| refused | 请求被拒绝 |

## [domain-set]段配置

域名集合配置

当[upstreams]上游dns服务器有多组时，域名集合用于分组名进行分流进行上游查询

### 案例

```toml
ad = { "list" = [
    # "/sys.prefix/etc/flexidns/list/anti-ad-domains.txt",
    # or
    "anti-ad-domains.txt",
], "domainname" = [] }


direct = { "list" = [
    "direct-list.txt",
    "google-cn.txt",
    "apple-cn.txt",
], "domainname" = [
    "ipv4.icanhazip.com",
    "ns1.digitalocean.com",
    "android.clients.google.com",
    "push.apple.com",
    "xn--ngstr-lra8j.com",
    "play-fe.googleapis.com",
    "www.googleapis.com",
    "cn.pool.ntp.org",
    "ipv4.icanhazip.com",
    "ns1.digitalocean.com",
] }

cn = { "list" = ['china-domains.txt'], "domainname" = [] }
cloudflare = { "list" = [], "domainname" = ["www.cloudflare.com"] }

proxy = { "list" = [
    "greatfire.txt",
    "proxy-list.txt",
    "mygfw.txt",
], "domainname" = [
] }
```

### 格式

* `set-name = { "list" = [set-file, ...], "domainname" = ["xx.com", ...] }`

集合名： 自定义字符串

> **NOTE: {}内 ’=’左边的"list"与“domainname”不可变**

## [[set-usage]]段配置

set-usage配置，将域名set分组或ip set分组与上游dns服务器进行绑定

```toml
[[set-usage]]
[set-usage.domain-set.ip-set]
cloudflare = "cloudflare"
cn = "cn"
[set-usage.domain-set.upstreams]
proxy = "proxy"
direct = "cn"
[set-usage.domain-set.blacklist]
ad = "ad"
```

> NOTE: 注意顺序：如果两个规则列表中有同一个域名，则该域名的规则, 下面的会覆盖上面的。也就是只有下面这个规则列表生效


> NOTE: `[set-usage.domain-set.ip-set]`, 方括号内不可变

```shell
[set-usage.domain-set.ip-set]
cloudflare = "cloudflare"
cn = "cn"
```

规则绑定: 等号左边域名集合名, 等号右边IP集合名

```toml
[set-usage.domain-set.upstreams]
proxy = "proxy"
direct = "cn"
```

> NOTE: `[set-usage.domain-set.upstreams]`, 方括号内不可变

规则绑定: 等号左边域名集合名, 等号右边上游DNS服务器分组名
