from distutils.core import setup
from setuptools import find_packages
import re

with open("lokey/__init__.py", "r") as fd:
    version = re.search(
        r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]', fd.read(), re.MULTILINE
    ).group(1)

if not version:
    raise RuntimeError("Cannot find version information")

download_url = "https://github.com/jpf/lokey/archive/{version}.tar.gz".format(
    version=version
)

requires = ["click", "cryptography", "requests", "python-hkp", "pgpy", "paramiko"]

setup(
    name="lokey",
    version=version,
    author="Joel Franusic",
    author_email="jfranusic@gmail.com",
    packages=find_packages(),
    description="A tool to convert between different cryptographic key formats",
    url="https://github.com/jpf/lokey",
    download_url=download_url,
    keywords=["rsa", "ssh", "pgp", "x509", "jwk"],
    classifiers=[],
    install_requires=requires,
    python_requires=">=3.8",
    entry_points="""
        [console_scripts]
        lokey=lokey:cli
    """,
)
