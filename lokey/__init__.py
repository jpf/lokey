#!/usr/bin/env python
import sys
import StringIO
import ssl as stdlib_ssl
import json
import pprint

import click
import requests
import paramiko
from hkp import KeyServer


# FIXME: Cleanup imports that we don't need
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import json

import pgpy

import datetime

from pgpy.packet.fields import RSAPub, MPI
from pgpy.packet.packets import PubKeyV4
from pgpy.constants import PubKeyAlgorithm

from jwt.algorithms import RSAAlgorithm

class ErisPublicNumbers(rsa.RSAPublicNumbers):
    def __init__(self, e=None, n=None):
        if e and n:
            super(ErisPublicNumbers, self).__init__(e, n)
        # with open("ca-key.pem", "r") as f:
        #     data = f.read()
        #     rv = serialization.load_pem_private_key(
        #         data,
        #         'passphrase',
        #         default_backend())
        #     self.ca_key = rv

    def to_openssh(self):
        # FIXME: verify that names are  correct
        # FIXME: Add docstring
        rsa_pub = self.public_key(default_backend())
        return(rsa_pub.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH)
        )

    def from_openssh(self, data):
        # FIXME: Add docstring
        key = serialization.load_ssh_public_key(data, default_backend())
        self._e = key.public_numbers().e
        self._n = key.public_numbers().n

    def to_jwk(self):
        # FIXME: Add docstring
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        # jwk_payload = algo.to_jwk(self.public_key(default_backend()))
        json_payload = json.loads(algo.to_jwk(self.public_key(default_backend())))
        del(json_payload['key_ops'])
        jwk_payload = json.dumps(json_payload)
        return jwk_payload

    def from_jwk(self, data):
        # FIXME: Add docstring
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        key = algo.from_jwk(data)
        self._e = key.public_numbers().e
        self._n = key.public_numbers().n

    def from_pgp(self, data):
        # FIXME: Add docstring
        pgp_key, _ = pgpy.PGPKey.from_blob(data)
        key_material = pgp_key._key.keymaterial
        self._e = key_material.e
        self._n = key_material.n

    def to_pgp(self):
        # FIXME: Add docstring
        rsa_pub = RSAPub()
        rsa_pub.e = MPI(self._e)
        rsa_pub.n = MPI(self._n)

        pub_key_v4 = PubKeyV4()
        pub_key_v4.pkalg = PubKeyAlgorithm.RSAEncryptOrSign
        pub_key_v4.keymaterial = rsa_pub
        pub_key_v4.update_hlen()

        # FIXME: Rename "good key"
        good_key = pgpy.PGPKey()
        good_key._key = pub_key_v4

        # FIXME: Paramerize the names below
        uid = pgpy.PGPUID.new('Abraham Lincoln',
                              comment='Honest Abe',
                              email='abraham.lincoln@whitehouse.gov')

        uid._parent = good_key
        good_key._uids.append(uid)
        return str(good_key)


    def from_pem(self, data):
        # FIXME: Add docstring
        key = serialization.load_pem_public_key(data, default_backend())
        self._e = key.public_numbers().e
        self._n = key.public_numbers().n

    def to_pem(self):
        rsa_pub = self.public_key(default_backend())
        return(rsa_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    
    def from_x509_pem(self, data):
        # FIXME: Add docstring
        cert = x509.load_pem_x509_certificate(data, default_backend())
        # pprint.pprint(cert.__dict__)
        key_material = cert.public_key().public_numbers()
        self._e = key_material.e
        self._n = key_material.n

    # https://cryptography.io/en/latest/x509/tutorial/#creating-a-self-signed-certificate
    # def to_x509_pem(self, serial_number=1):
    #     # FIXME: Add docstring
    #     rsa_pub = rsa.RSAPublicNumbers(
    #         self._e,
    #         self._n).public_key(default_backend())
    #     subject = issuer = x509.Name([
    #         x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    #         x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
    #         x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
    #         x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
    #         x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
    #     ])
    #     cert = x509.CertificateBuilder().subject_name(
    #         # FIXME: Determine this from outside state
    #         subject
    #     ).issuer_name(
    #         # FIXME: This should be different than subject!
    #         issuer
    #     ).public_key(
    #         # FIXME: This can be cleaner
    #         rsa_pub
    #     ).serial_number(
    #         # FIXME: This should come from outside state
    #         serial_number
    #     ).not_valid_before(
    #         datetime.datetime.utcnow()
    #     ).not_valid_after(
    #         # FIXME: Make this configurable
    #         # Our certificate will be valid for 10 days
    #         datetime.datetime.utcnow() + datetime.timedelta(days=10)
    #     ).add_extension(
    #         # FIXME: Make this configurable
    #         x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
    #         critical=False,
    #         # FIXME: Generate this if possible, or if it doesn't exit already
    #         # Sign our certificate with our private key
    #     ).sign(self.ca_key, hashes.SHA256(), default_backend())
    #     return cert.public_bytes(serialization.Encoding.PEM)

    def load(self, f):
        bytes_to_use_for_guess = 20
        method = None
        hint = f.read(bytes_to_use_for_guess)
        if hint.startswith('-----BEGIN CERT'):
            method = self.from_x509_pem
        elif hint.startswith('-----BEGIN PGP '):
            method = self.from_pgp
        elif hint.startswith('ssh-rsa '):
            method = self.from_openssh
        elif '{' in hint and '"' in hint:
            method = self.from_jwk
        if method:
            mebibyte_in_bytes = 1048576
            data = hint
            data += f.read(mebibyte_in_bytes)
            method(data)


@click.group(invoke_without_command=True)
@click.version_option("0.0.2")
@click.pass_context
def cli(ctx):
    if sys.__stdin__.isatty():
        # FIXME: Write text below
        # print "Usage"
        # print "Examples"
        return
    # FIXME: Rename "load" to "detect_key_type"
    ctx.obj.load(sys.stdin)
    if not ctx.invoked_subcommand:
        # FIXME: Print out "key text"
        print "Got this: "
        print ctx.obj

@cli.group()
@click.pass_context
def to(ctx):
    """Convert key in STDIN to another format"""
    # FIXME: Write better description for this subcommand ^
    # FIXME: Write error handler for commands that we don't get
    # method_name = "to_" + format
    # rv = getattr(ctx.obj, method_name)()
    # print rv
    pass

# @to.command()
# @click.pass_context
# # @click.option('--kid', help='')
# # @click.option('--for-signing/--not-for-signing',
# #               default=True,
# #               help='Should key be used for signing data?')
# # @click.option('--for-encryption/--not-for-encryption',
# #               default=True,
# #               help='Should key be used for encrypting data?')
# def jwk(ctx):
#     """JWK format"""
#     key = ctx.obj.to_jwk()
#     print(key)

    
# @to.command()
# @click.pass_context
# # @click.option('--country', help='')
# # @click.option('--state', '--province', help='')
# # @click.option('--city', '--locality', help='')
# # @click.option('--company', '--organization', help='')
# # @click.option('--common-name', help='')
# # @click.option('--serial-number', help='')
# # @click.option('--valid-for', type=int, help='')
# def x509(ctx):
#     """X.509 certificate format"""
#     key = ctx.obj.to_x509_pem()
#     print(key)
    
@to.command()
@click.pass_context
@click.option('--comment', help='Comment to use in the SSH key')
def openssh(ctx, comment):
    """OpenSSH key format"""
    key = ctx.obj.to_openssh()
    print(key)
    
@to.command()
@click.pass_context
def pem(ctx):
    """PEM encoded key format"""
    key = ctx.obj.to_pem()
    print(key)
    
@to.command()
@click.pass_context
# @click.option('--username', help='Username to use in PGP key')
# @click.option('--comment', help='Comment to use in PGP key')
# @click.option('--email', help='Email address to use for PGP key')
def pgp(ctx):
    """PGP key format"""
    key = ctx.obj.to_pgp()
    print(key)
    
@cli.group()
@click.pass_context
def fetch(ctx):
    """Fetch key from place"""
    pass

@fetch.command()
@click.pass_context
def keybase(ctx):
    """NOT IMPLEMENTED YET"""
    pass

@fetch.command()
@click.pass_context
@click.argument('domain_name')
def ssh(ctx, domain_name):
    """Fetch public key from an SSH server"""

    class FetchKeyPolicy(paramiko.MissingHostKeyPolicy):
        def __init__(self):
            self.key = None

        def missing_host_key(self, client, hostname, key):
            self.key = key

    fetch_key_policy = FetchKeyPolicy()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(fetch_key_policy)
    client.connect(domain_name, username='maii')
    key = fetch_key_policy.key.public_numbers
    eris = ErisPublicNumbers(e=key.e, n=key.n)
    print eris.to_openssh()

@fetch.command()
@click.pass_context
@click.argument('domain_name')
@click.option('--kid', '--key-id', type=int, help="Key ID ('kid') to print")
def jwk(ctx, domain_name, key_id):
    """Fetch JWK keys for a domain"""
    url = 'https://{domain_name}/.well-known/openid-configuration'.format(domain_name=domain_name)
    r = requests.get(url)
    resp = r.json()
    if 'jwks_uri' not in resp:
        print("Error fetching {url}".format(url=url))
    url = resp['jwks_uri']
    r = requests.get(url)
    resp = r.json()
    keys = resp['keys']

    if not len(keys) > 0:
        click.echo("No keys found for '{}'".format(domain_name), err=True)
        return
    if not key_id and len(keys) > 1:
        click.echo("Multiple keys found: ", err=True)
        for key in keys:
            click.echo("  - {}".format(key['kid']), err=True)
        click.echo("Printing the first key ('{}')".format(keys[0]['kid']), err=True)
    key_id_to_print = None
    if key_id:
        key_id_to_print = key_id
    else:
        key_id_to_print = keys[0]['kid']
    for key in keys:
        if key['kid'] != key_id_to_print:
            continue
        print json.dumps(key)


@fetch.command()
@click.pass_context
@click.argument('github_username')
@click.option('--key-id', type=int, help="ID of GitHub user key to print")
def github(ctx, github_username, key_id):
    """Fetch user key from GitHub"""
    url = 'https://api.github.com/users/{github_username}/keys'.format(
        github_username=github_username)
    r = requests.get(url)
    keys = r.json()
    if not len(keys) > 0:
        click.echo("No keys found for user '{}'".format(github_username), err=True)
        return
    if not key_id and len(keys) > 1:
        click.echo("Multiple keys found: ", err=True)
        for key in keys:
            click.echo("  - {}".format(key['id']), err=True)
        click.echo("Printing the first key ('{}')".format(keys[0]['id']))
    key_id_to_print = None
    if key_id:
        key_id_to_print = key_id
    else:
        key_id_to_print = keys[0]['id']
    for key in keys:
        if key['id'] != key_id_to_print:
            continue
        print key['key']


@fetch.command()
@click.pass_context
@click.argument('domain_name')
def tls(ctx, domain_name):
    """Fetch TLS certificate for domain name"""
    cert = stdlib_ssl.get_server_certificate((domain_name, 443))
    click.echo(cert)


@fetch.command()
@click.pass_context
@click.argument('search_string')
@click.option('--key-id', help="ID of PGP key to print")
@click.option('--all', is_flag=True, default=False, help="Search all keyservers")
@click.option('--server', help="PGP keyserver to search")
def pgp(ctx, search_string, key_id, all, server):
    '''Search for PGP key on the following keyservers until a match is found:

       - pool.sks-keyservers.net

       - keys.gnupg.net

       - pgp.mit.edu

       - keyserver.ubuntu.com

       - zimmermann.mayfirst.org
    '''

    servers = []
    if server:
        servers.append(server)
    else:
        doc = pgp.__doc__
        for line in doc.split("\n"):
            delimiter = '       - '
            if not line.startswith(delimiter):
                continue
            server = line.replace(delimiter, '')
            servers.append(server)

    for server in servers:
        addr = 'http://{}'.format(server)
        click.echo('Searching {}'.format(addr), err=True)
        serv = KeyServer(addr)
        responses = serv.search(search_string)
        # FIXME: DRY up this bit of code with jwk code too
        keys = []
        for key in responses:
            if 'RSA' in key.algo:
                keys.append(key)
        if not key_id and len(keys) > 1:
            click.echo("Multiple keys found: ", err=True)
            for key in keys:
                click.echo("  - {}".format(key.keyid), err=True)
            click.echo("Printing the first key ('{}')".format(keys[0].keyid), err=True)
        key_id_to_print = None
        if key_id:
            key_id_to_print = key_id
        else:
            key_id_to_print = keys[0].keyid
        for key in keys:
            if key.keyid != key_id_to_print:
                continue
            print key.key
        if not all:
            return


if __name__ == '__main__':
    epn = ErisPublicNumbers()
    # FIXME: Don't define 'obj' as Eris. Find a better way
    cli(obj=epn)
