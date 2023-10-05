# 打包文件
# 打包完成后，可以使用命令查看包内容： python3 -m zipfile -l dist/xxx.whl
# 打包完成后，可以使用命令查看包元数据： pkginfo -f requires_dist  dist/xxx.whl

# from setuptools.command.install_scripts import install_scripts
from setuptools import setup
import sys
sys.path.append('/home/guocl/Python/proj003/src/')

import FlexiDNS


# requirements = open('requirements.txt').readlines()

setup(
    # name=FlexiDNS.PACKAGE_NAME,
    # version=FlexiDNS.__version__,
    # author='GuoCL',
    # author_email='',
    # python_requires='>=3.11',
    # description='a dns server in python',
    # platforms='x86_64',
    # license='GPL',
    # setup_requires=['setuptools'],
    # packages=find_packages(where='src', include=[
                        #    'src/FlexiDNS*'], exclude=['src/tests*']),
    # package_dir={'flexidns': 'src/FlexiDNS'},
    # classifiers=[
    #     'License :: OSI Approved :: Python Software Foundation License', 'Programming Language :: Python :: 3.11',
    #     'Development Status :: 3 - Alpha', 'perating System :: POSIX :: Linux', 'Topic :: Internet'
    # ],
    # install_requires=requirements,
    # scripts=['src/flexidns'],
    # data_files=[
    #     ('etc/flexidns', ['src/etc/flexidns/config.toml']),
    #     ('lib/systemd/system', ['flexidns.service']),
    #     ('etc/flexidns/ssl', ['src/etc/flexidns/ssl/ca.cer',
    #      'src/etc/flexidns/ssl/guocl.cc.cer', 'src/etc/flexidns/ssl/guocl.cc.key']),
    #     ('etc/flexidns/list', [
    #         'src/etc/flexidns/list/anti-ad-domains.txt', 'src/etc/flexidns/list/google-cn.txt',
    #         'src/etc/flexidns/list/apple-cn.txt', 'src/etc/flexidns/list/direct-list.txt', 'src/etc/flexidns/list/mydirect.txt',
    #         'src/etc/flexidns/list/mygfw.txt', 'src/etc/flexidns/list/telegram.txt', 'src/etc/flexidns/list/cloudflare.txt',
    #         'src/etc/flexidns/list/cn-all.txt', 'src/etc/flexidns/list/proxy-list.txt', 'src/etc/flexidns/list/greatfire.txt',
    #         'src/etc/flexidns/list/hosts'
    #     ])
    # ],
    )
