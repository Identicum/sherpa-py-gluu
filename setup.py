# sherpa-py-gluu is available under the MIT License. https://github.com/Identicum/sherpa-py-gluu/
# Copyright (c) 2025, Identicum - https://identicum.com/
#
# Author: Gustavo J Gallardo - ggallard@identicum.com
#

from setuptools import setup

setup(
    name='sherpa-py-gluu',
    version='1.0.20250512',
    description='Python utilities for Gluu',
    url='git@github.com:Identicum/sherpa-py-gluu.git',
    author='Identicum',
    author_email='ggallard@identicum.com',
    license='MIT License',
    install_requires=['python-ldap', 'ldif', 'pyDes', 'sherpa-py-utils'],
    packages=['sherpa.gluu'],
    zip_safe=False,
    python_requires='>=3.0'
)

