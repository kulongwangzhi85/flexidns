#!/usr/bin/env python3

# coding: utf-8

import unittest

suites = unittest.defaultTestLoader.discover('.', pattern='test_*.py')
runner = unittest.TextTestRunner()
runner.run(suites)