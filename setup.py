#!/usr/bin/env python3
# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
import os
from toripscanner import __version__


here = os.path.abspath(os.path.dirname(__file__))


def long_description():
    with open(os.path.join(here, 'README.md'), encoding='utf-8') as f:
        return f.read()


def get_package_data():
    return [
        'config.default.ini',
        'config.log.default.ini',
        'parse-header.txt',
    ]


def get_data_files():
    pass


setup(
    name='TorIPScanner',
    version=__version__,
    description='Scan Tor exits for the IPs they use.',
    long_description=long_description(),
    long_description_content_type='text/markdown',
    author='Matt Traudt',
    author_email='pastly@torproject.org',
    license='MIT',
    url='https://github.com/oftc/TorIPScanner',
    classifiers=[
        'Development Status :: 4 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.7',
        'Topic :: System :: Networking',
    ],
    packages=find_packages(),
    include_package_data=True,
    package_data={
        'relayscan': get_package_data(),
    },
    # data_files=get_data_files(),
    keywords='tor measurement scanner relay exit',
    python_requires='>=3.7.3',
    entry_points={
        'console_scripts': [
            'toripscanner = toripscanner.toripscanner:main',
        ]
    },
    install_requires=[
        'stem==1.8.0',
        'PySocks==1.7.1',
        # 'cbor2==5.2.0',
    ],
    extras_require={
        # 'dev': ['flake8==3.8.1', 'vulture==1.4', 'mypy==0.770'],
        # 'doc': ['sphinx==3.0.3', 'sphinx-autodoc-typehints==1.10.3'],
        # 'test': ['tox==3.15.1', 'pytest==5.4.2', 'coverage==5.1'],
        'dev': ['flake8==3.9.2', 'mypy==0.910', 'vulture==2.3'],
    },
)
