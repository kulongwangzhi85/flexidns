
# coding: utf-8

from importlib import metadata

PACKAGE_NAME = __package__.split('.')[1] if len(__package__.split('.')) > 1 else __package__
VERSION = "1.3.0.dev4"

try:
    __version__ = metadata.version(PACKAGE_NAME)
except metadata.PackageNotFoundError:
    __version__ = VERSION

# version = '1.2.3.dev9+g3b9fee8'
# g:为git工具，后面的hash值为git commit id
