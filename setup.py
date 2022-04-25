from setuptools import setup, find_packages

setup(
    name = 'morion',
    version = '0.0.1',
    packages = find_packages(include = ['morion', 'morion.*']),
    install_requires = [
        'termcolor==1.1.0',
        'keystone-engine==0.9.2',
##        'PyYAML==6.0',
##        'ipython==8.1.1'
    ],
    entry_points = {
        'console_scripts': [
            'morion=morion.symbex.execute:main',
##            'morion_backward_slicer=',
            'morion_control_hijacker=morion.symbex.hijack_control:main',
##            'morion_memory_hijacker=',
##            'morion_branch_analyzer=',
##            'morion_path_analyzer='
        ]
    }
)
