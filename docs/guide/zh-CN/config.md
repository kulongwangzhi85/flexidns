
1. hosts配置
配置文件格式采用与linux系统下的/etc/hosts文件格式相同，
一行一个规则，一个域名可配置多个ipv4与ipv6地址
\#为注释行，将该行设置为不生效行
**格式**
`IP DOMAINNAME`

### RCode - dns响应代码
| RCode | 描述 |
| --- | --- |
| success | 无错误 |
| format_error | 请求格式错误 |
| server_failure | 服务器出错 |
| name_error | 域名不存在 |
| not_implemented | 功能未实现 |
| refused | 请求被拒绝 |