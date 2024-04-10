
# coding: utf-8

"""
dns服务器的日志初始化模块，采用QueueListener的方式接收日志到该队列中
使用dnsadapter方法，获取上下文信息，并记录到日志中
"""

from logging.handlers import QueueHandler, RotatingFileHandler, QueueListener, SysLogHandler
from logging import ERROR, Formatter, getLogger, Filter, LoggerAdapter
from multiprocessing import Queue
logqueue = Queue()


class dnsidAdapter(LoggerAdapter):
    """自动添加上下文变量中的上下文信息到日志中
    """

    def process(self, msg, kwargs):
        from dnslib import QTYPE
        funcObj = self.extra['dnsinfo']
        if funcObj:
            info = funcObj.get()
            if info:
                address = info.get('address')
                id = info.get('id')
                qname = info.get('qname')
                qtype = QTYPE.get(info.get('qtype'))
            else:
                address = None
                id = None
                qname = None
                qtype = None
        else:
            id = None
            qname = None
            qtype = None
        kwargs['extra'] = {'ip': address, 'dnsid': id,
                           'qname': qname, 'qtype': qtype}
        return msg, kwargs

class LogTooLongFilter(Formatter):
    """
    用于检查单行日志长度
    """
    def __init__(self, msg_length = 200):

        fmt='%(asctime)s.%(msecs)03d [ %(levelname)s %(module)s L%(lineno)d <%(ip)s> id: %(dnsid)s qname: %(qname)s qtype: %(qtype)s ] - %(message)s'
        datefmt='%Y/%m/%d %H:%M:%S'
        defaults={'ip': None, 'dnsid': None, 'qname': None, 'qtype': None}

        super(LogTooLongFilter, self).__init__(
                fmt=fmt,
                datefmt=datefmt,
                defaults=defaults
                )
        self.msg_length = msg_length

    def format(self, record):
        if len(record.msg) >= self.msg_length:
            record.msg = record.msg[:self.msg_length] + ' ... ...'
        return super().format(record)

class MyLevelFilterError(Filter):

    def filter(self, record):
        if record.levelno >= ERROR:
            return True
        return False


class MyLevelFilterNoneError(Filter):

    def filter(self, record):
        if record.levelno >= ERROR:
            return False
        return True


def loggerconfigurer():
    from .dnstoml import configs, share_objects
    loglevel = configs.loglevel
    logfile = configs.logfile
    logerror = configs.logerror
    loglevels = share_objects.LOGLEVELS
    network_log_server = configs.network_log_server

    root = getLogger()
    root.setLevel(loglevels.get(loglevel))

    pylog_fmt = Formatter(
        fmt='%(asctime)s.%(msecs)03d [ %(levelname)s %(module)s L%(lineno)d <%(ip)s> id: %(dnsid)s qname: %(qname)s qtype: %(qtype)s ] - %(message)s',
        datefmt=configs.logdatefmt,
        style='%',
        defaults={'ip': None, 'dnsid': None, 'qname': None, 'qtype': None},
        validate=True)
    # pylog_fmt = LogTooLongFilter()

    rotat_handler = RotatingFileHandler(
        logfile,
        maxBytes=configs.logfile_size,
        mode='a',
        delay=False,
        backupCount=configs.logfile_backupcount,
        encoding='utf-8'
    )
    rotat_handler.setLevel(loglevels.get(loglevel))
    # rotat_handler.addFilter(MyLevelFilterNoneError())
    rotat_handler.setFormatter(pylog_fmt)

    if loglevels.get(loglevel) < ERROR:
        """
        配置文件中设置日志level为ERROR时，不会注册ERROR日志到单独日志文件
        """
        rotat_handler_error = RotatingFileHandler(
            logerror,
            maxBytes=configs.logfile_size,
            mode='a',
            delay=False,
            backupCount=configs.logfile_backupcount,
            encoding='utf-8'
        )
        rotat_handler_error.setLevel(ERROR)
        rotat_handler_error.addFilter(MyLevelFilterError())
        rotat_handler_error.setFormatter(pylog_fmt)

        logger_handlers = [rotat_handler, rotat_handler_error]
    else:
        logger_handlers = [rotat_handler]

    if network_log_server:
        datagram_handler = SysLogHandler(network_log_server)
        datagram_handler.setLevel(loglevels.get(loglevel))
        datagram_handler.setFormatter(pylog_fmt)
        logger_handlers.append(datagram_handler)

    qh = QueueHandler(logqueue)
    qh.setLevel(loglevels.get(loglevel))
    root.addHandler(qh)

    listener = QueueListener(logqueue, *logger_handlers)
    return listener


if __name__ == '__main__':
    from os import _exit
    _exit(0)
