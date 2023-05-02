from setuptools import setup, find_packages

setup(
    name = 'morion',
    version = '0.0.9',
    packages = find_packages(include = ['morion', 'morion.*']),
    install_requires = [
        'termcolor==2.3.0',
        'keystone-engine==0.9.2',
        'PyYAML==6.0',
        'ipython==7.34.0'
    ],
    entry_points = {
        'console_scripts': [
            'morion=morion.symbex.execute:main',
            'morion_pwndbg=morion.pwndbg:main',
            'morion_backward_slicer=morion.symbex.backward_slice:main',
            'morion_control_hijacker=morion.symbex.hijack_control:main',
            'morion_memory_hijacker=morion.symbex.hijack_memory:main',
            'morion_branch_analyzer=morion.symbex.analyse_branches:main',
            'morion_path_analyzer=morion.symbex.analyse_paths:main'
        ]
    }
)
