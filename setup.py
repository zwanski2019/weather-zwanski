from setuptools import setup, find_packages

setup(
    name='decryptor',
    version='0.1.0',
    packages=find_packages(),
    install_requires=[
        'cryptography',
    ],
    entry_points={
        'console_scripts': [
            'decryptor=decryptor.decryptor:main',
        ],
    },
)
