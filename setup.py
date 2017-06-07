#!/usr/bin/env python

import os
from setuptools import setup, find_packages
from pip.req import parse_requirements

setup_dir = os.path.dirname(os.path.realpath(__file__))
path_req = os.path.join(setup_dir, 'requirements.txt')
install_reqs = parse_requirements(path_req, session=False)

reqs = [str(ir.req) for ir in install_reqs]

setup(name='MrMime',
      author = 'sLoPPydrive',
      description = 'Pokemon GO client library mimicing the original app',
      version = '0.0.1',
      url = 'https://github.com/sLoPPydrive/MrMime',
      download_url = "https://github.com/sLoPPydrive/MrMime/releases",
      packages = find_packages(),
      install_requires = reqs
      )
