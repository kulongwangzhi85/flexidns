#!/usr/bin/env python3

import sys, os
sys.path.insert(0, os.path.split(__file__)[0])

from os import _exit
from git import Repo, InvalidGitRepositoryError

from FlexiDNS.__init__ import VERSION

def get_git_commit_id():
    # 获取 git 仓库的当前提交 id
    try:
        repo = Repo(search_parent_directories=True)
    except InvalidGitRepositoryError:
        return None
    else:
        return repo.head.object.hexsha[:7]

def get_version_info():
    # 返回version信息
    git_commit_id = get_git_commit_id()

    if git_commit_id is not None:
        version = f"{VERSION}+g{git_commit_id}"
    else:
        version = VERSION

    return version

version = get_version_info()

if __name__ == '__main__':
    _exit(0)
