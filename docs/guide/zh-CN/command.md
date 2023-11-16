# flexidns子命令

flexidns目前提供cache缓存与rules规则在线设置

rules子命令用于修改默认情况下的规则

> **NOTE: rules需要在有多个上游DNS分组情况才有意义**

> **rules与cache操作变更后，会根据缓存持久化一同保存**

## 查看帮助

```shell
flexidns --help
```

### 输出

```shell
usage: FlexiDNS [-h]  ...

Python Code Dns Server Cmd Line Options

options:
  -h, --help  show this help message and exit

flexidns cli:
              flexidns server server operate command, use {start, stop, cache, rules, version} -h/--help for more information
    cache     dns cache operate cli
    start     start dns server
    stop      stop dns server
    rules     domain name rule operate cli
    version   display FlexiDNS version

```

### cache子命令帮助

```shell
flexidns cache  --help
```

```shell
usage: FlexiDNS cache [-h]  ...

options:
  -h, --help  show this help message and exit

cache subcommands:
  
    show      show dns cache
    delete    delete dns cache
```

### rules子命令帮助

```shell
flexidns rules  --help
```

```shell
usage: FlexiDNS rules [-h] [-n <domain name> [<domain name> ...]] [-d <domain name> [<domain name> ...]] [-r <new rule>] [-c] [-s]

options:
  -h, --help            show this help message and exit
  -n <domain name> [<domain name> ...], --name <domain name> [<domain name> ...]
                        view or modify specitied domain name rule information
  -d <domain name> [<domain name> ...], --delete <domain name> [<domain name> ...]
                        delete specitied domain name rule from rules cacheed
  -r <new rule>, --rule <new rule>
                        modify rule to new rule
  -c, --count           view rule counts
  -s, --show            display dns rules

```

## 查看版本

```shell
flexidns version
```

## start子命令

```shell
flexidns start --help
```

```shell
usage: FlexiDNS start [-h] -c <toml config file>

options:
  -h, --help            show this help message and exit
  -c <toml config file>, --config <toml config file>
                        dns server config file
```

## rules子命令

查看rules名(其实就是配置文件中的分组名)

```shell
flexidns rules -s
```

```shell
rules: ['ad', 'direct', 'cn', 'cloudflare', 'proxy']
```

查看一个域名或多个域名的rule

> **支持通配符**

```shell
flexidns rules -n www.baidu.com
```

```shell
+----------------+--------+
|   query name   |  rule  |
+----------------+--------+
| www.baidu.com. | direct |
+----------------+--------+
```

修改一个或多个域名的rule

```shell
flexidns rules -n www.baidu.com -r proxy
```

```shell
+----------------+-------+
|   query name   |  rule |
+----------------+-------+
| www.baidu.com. | proxy |
+----------------+-------+
```

## cache子命令

```shell
root@Gateway:~# flexidns cache show -h
```

```shell
usage: FlexiDNS cache show [-h] (-n <domain name> [<domain name> ...] | -a)

options:
  -h, --help            show this help message and exit
  -n <domain name> [<domain name> ...], --name <domain name> [<domain name> ...]
                        show one dns domain name record
  -a, --all             show all dns domain name record
```

```shell
flexidns cache delete -h
```

```shell
usage: FlexiDNS cache delete [-h] [-n <domain name> [<domain name> ...]]

options:
  -h, --help            show this help message and exit
  -n <domain name> [<domain name> ...], --name <domain name> [<domain name> ...]
                        delete one dns domain name record
```
