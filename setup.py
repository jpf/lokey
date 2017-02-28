from distutils.core import setup
setup(
    name = 'lokey',
    packages = ['lokey'],
    version = '0.0.2',
    description = 'A tool to convert between different cryptographic key formats',
    author = 'Joel Franusic',
    author_email = 'jfranusic@gmail.com',
    url = 'https://github.com/jpf/lokey',
    download_url = 'https://github.com/jpf/lokey/archive/0.0.2.tar.gz',
    keywords = ['rsa', 'ssh', 'pgp', 'x509', 'jwk'], 
    classifiers = [],
    install_requires = ['click', 'cryptography', 'requests', 'python-hkp', 'pgpy', 'pyjwt', 'paramiko'],
    entry_points = '''
        [console_scripts]
        lokey=lokey:cli
    '''
    
)
