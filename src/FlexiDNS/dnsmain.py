
# coding: utf-8

"""
dns服务主进程，发起配置初始化，服务启动功能
"""

import fcntl
import os
import signal
import sys
import stat
from threading import local, Thread

from .tomlconfigure import configs

local_school = local()


def async_mp(server):
    def wrapper(*args, **kwargs):
        from multiprocessing import Process
        mp = Process(target=server, args=args, kwargs=kwargs)
        mp.daemon = True
        mp.start()
        return mp
    return wrapper


def async_thread(server):
    def wrapper(*args, **kwargs):
        th = Thread(target=server, args=args, kwargs=kwargs)
        th.daemon = True
        th.start()
        return th
    return wrapper


def signal_exit_server(signum, frame):
    from .tomlconfigure import configs
    if os.path.exists(configs.sockfile):
        os.remove(configs.sockfile)
    if os.path.exists(configs.mmapfile):
        os.remove(configs.mmapfile)
    if local_school.start_server.is_alive():
        local_school.start_server.join()
        local_school.start_server.close()


def write_pid_file(pid, PIDFILE):

    pid_desc = os.open(PIDFILE, os.O_CREAT | os.O_RDWR,
                       stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    try:
        fcntl.lockf(pid_desc, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError as err:
        print(err, file=sys.stderr, flush=True)
        return False
    os.truncate(pid_desc, 0)
    s_pid = f"{str(pid)}\n"
    os.write(pid_desc, s_pid.encode('utf8'))
    os.chmod(PIDFILE, 0o644)
    return True


@async_thread
def start_ttlout_server():
    from .dnsttlout import start
    start()


@async_mp
def start_server():
    from .dnscache import module_init as cache_init
    from .dnsrules_new import module_init as rules_init
    cache_init()
    rules_init()
    from .dnsserver import start
    start()


def main(configfile):
    pid = os.fork()
    if pid > 0:
        sys.exit(0)

    os.setsid()
    os.umask(0o026)

    if os.fork() > 0:
        sys.exit(0)

    os.setpgrp()

    PID = os.getpid()
    if write_pid_file(PID, configs.pidfile) is False:
        os._exit(1)

    from .dnslog import loggerconfigurer
    from .tomlconfigure import loader_config
    from logging import getLogger
    loader_config(configfile)

    local_school.queue_listener = loggerconfigurer()
    local_school.queue_listener.start()
    logger = getLogger(__name__)
    # logger.info(f'Start dns server, pid: {PID}') #不知为何执行该条语句会多出一条线程,注释后正常

    sys.stdout.flush()
    sys.stderr.flush()

    with open('/dev/null', 'r') as f:
        os.dup2(f.fileno(), sys.stdin.fileno())
    with open(configs.logfile, 'a+') as f:
        os.dup2(f.fileno(), sys.stdout.fileno())
    with open(configs.logerror, 'a+') as f:
        os.dup2(f.fileno(), sys.stderr.fileno())

    local_school.start_server = start_server()
    local_school.start_ttlout_server = start_ttlout_server()

    signal.signal(signal.SIGINT, signal_exit_server)
    signal.signal(signal.SIGTERM, signal_exit_server)

    for i in (local_school.start_server, local_school.start_ttlout_server):
        i.join()

    os.remove(configs.pidfile)
    logger.info('Shutdown dns server')
    local_school.queue_listener.stop()


def stop_server():
    """使用命令行模式下，stop选项来发送signal.SIGINT信号，给pid，以执行signal_exit_server方法
    并执行清理操作
    """
    try:
        with open(f'/run/{__package__}.pid', 'r') as f:
            try:
                PGID = os.getpgid(int(f.read()))
            except OSError:
                print('Process not found', file=sys.stderr, flush=True)
                os._exit(1)
    except FileNotFoundError:
        print('Process not found', file=sys.stderr, flush=True)
        os._exit(1)
    os.killpg(PGID, signal.SIGINT)


if __name__ == '__main__':
    os._exit(0)
