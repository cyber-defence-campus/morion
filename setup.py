from setuptools import setup, find_packages

setup(
    name = 'morion',
    version = '0.0.1',
    packages = find_packages(include = ['morion', 'morion.*']),
    install_requires = [
        'termcolor==1.1.0',
##        'keystone-engine==0.9.2',
##        'PyYAML==6.0',
##        'ipython==8.1.1'
    ],
    entry_points = {
##        'console_scripts': ['concolex=concolex.dbg:main']
    }
)
