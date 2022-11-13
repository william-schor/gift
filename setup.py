from setuptools import find_packages, setup

requirements = [
    'click',
    'cryptography',
    'alive_progress'
]

setup(
    name='gift',
    version='0.1.0',
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
    extras_require={
        'dev': [
            'pytest',
            'types-setuptools',
            'mypy'
        ]
    },
    entry_points={
        'console_scripts': [
            'gift = gift.main:cli',
        ],
    },
)