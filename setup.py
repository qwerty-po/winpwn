from setuptools import *

setup(
    name='wpwn',
    version='0.2.0',
    description='windows pwntools',
    author='qwerty',
    author_email='qw3rtyp0@gmail.com',
    license='MIT',
    url="https://github.com/qwerty-po/winpwn",
    packages=find_packages(),
    install_requires=[
        'lief',
        'capstone',
        'keystone'
    ]
)
