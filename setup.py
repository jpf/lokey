from distutils.core import setup
from setuptools import find_packages
setup(
    name = 'lokey',
    packages = find_packages(),
    version = '0.4.0',
    description = 'A tool to convert between different cryptographic key formats',
    author = 'Joel Franusic',
    author_email = 'jfranusic@gmail.com',
    url = 'https://github.com/jpf/lokey',
    download_url = 'https://github.com/jpf/lokey/archive/0.4.0.tar.gz',
    keywords = ['rsa', 'ssh', 'pgp', 'x509', 'jwk'], 
    classifiers = [],
    install_requires = ['click', 'cryptography', 'requests', 'python-hkp', 'pgpy', 'paramiko'],
    entry_points = '''
        [console_scripts]
        lokey=lokey:cli
    '''
    
)
