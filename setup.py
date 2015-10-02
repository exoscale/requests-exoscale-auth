# coding: utf-8
from setuptools import setup

with open('README.rst', 'r') as f:
    long_description = f.read()

setup(
    name='requests-exoscale-auth',
    version='1.0',
    url='https://github.com/exoscale/requests-exoscale-auth',
    license='BSD',
    author=u'Exoscale',
    description=('Exoscale APIs support for Python-Requests.'),
    long_description=long_description,
    py_modules=('exoscale_auth',),
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    classifiers=(
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
    ),
    install_requires=(
        'requests',
    ),
)
