from setuptools import setup, find_packages

setup(
    name = 'morion',
    version = '0.1.5',
    author = 'Damian Pfammatter',
    description = 'Morion is a PoC tool to experiment with symbolic execution on real-world (ARMv7) binaries.',
    packages = find_packages(include = ['morion', 'morion.*']),
    install_requires = [
        'ipython==8.23.0',
        'keystone-engine==0.9.2',
        'PyYAML==6.0.1',
        'termcolor==2.4.0'
    ],
    entry_points = {
        'console_scripts': [
            'morion=morion.symbex.tools.execute:main',
            'morion_pwndbg=morion.pwndbg:main',
            'morion_backward_slicer=morion.symbex.tools.backward_slice:main',
            'morion_control_hijacker=morion.symbex.tools.hijack_control:main',
            'morion_memory_hijacker=morion.symbex.tools.hijack_memory:main',
            'morion_branch_analyzer=morion.symbex.tools.analyse_branches:main',
            'morion_path_analyzer=morion.symbex.tools.analyse_paths:main',
            'morion_rop_generator=morion.symbex.tools.generate_rop:main'
        ]
    }
)
