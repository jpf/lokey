#!/usr/bin/env python
__title__ = "lokey"
__version__ = "0.6.0"
__author__ = "Joel Franusic"
__license__ = "GPL 3.0"
__copyright__ = "Copyright 2017-2020 Joel Franusic"

import sys
import ssl as stdlib_ssl
import json

import click
import requests
import paramiko
import eris
from eris import ErisPublic

# from hkp import KeyServer


class LokeyContext:
    def __init__(self):
        self.key = None


@click.group(invoke_without_command=True)
@click.version_option("0.5.0")
# FIXME: I'm not happy with the idea of passing a password on the command line,
#        this needs to be fixed ASAP
@click.option(
    "--password", required=False, default=None, help="Password for private keys."
)
@click.pass_context
def cli(ctx, password):
    if not hasattr(ctx.obj, "key"):
        ctx.obj = LokeyContext()
    interactive_terminal = sys.__stdin__.isatty()
    subcommand = ctx.invoked_subcommand
    if interactive_terminal and not subcommand:
        print(
            "\n".join(
                [
                    ctx.get_help(),
                    "",
                    "Examples:",
                    "  $ cat your-key | lokey to ssh",
                    "  $ lokey fetch keybase twitter:jf",
                    "",
                ]
            )
        )
        return
    elif interactive_terminal and subcommand:
        return
    try:
        ctx.obj.key = eris.load(sys.stdin, password=password)
    except Exception as e:
        raise click.ClickException(str(e))
    if not subcommand:
        print(ctx.obj.key)


@cli.group()
@click.pass_context
def to(ctx):
    """Convert a key from STDIN into another format.

    Examples:

        $ cat your-key | lokey to pgp

        $ cat your-key | lokey to ssh

        $ cat your-key | lokey to pem
    """
    pass


@to.command()
@click.pass_context
# Future use:
# KID should default to fingerprint, but allow for manual override
# @click.option('--kid', help='')
# @click.option('--for-signing/--not-for-signing',
#               default=True,
#               help='Should key be used for signing data?')
# @click.option('--for-encryption/--not-for-encryption',
#               default=True,
#               help='Should key be used for encrypting data?')
def jwk(ctx):
    """JWK format."""
    print(ctx.obj.key.to("jwk"))


@to.command()
@click.pass_context
@click.option("--country", default="US", help="Country")
@click.option("--state", default="California", help="State")
@click.option("--city", default="San Francisco", help="City")
@click.option("--company", default="Lokey Example", help="Country")
@click.option("--common-name", default="www.example.com", help="Common Name")
def csr(ctx, country, state, city, company, common_name):
    """Certificate Signing Request."""
    print(
        ctx.obj.key.to(
            "csr",
            country=country,
            state=state,
            city=city,
            company=company,
            common_name=common_name,
        )
    )


@to.command()
@click.pass_context
@click.option("--comment", help="Comment to use in the SSH key.")
def ssh(ctx, comment):
    """OpenSSH key format."""
    print(ctx.obj.key.to("ssh", comment=comment))


@to.command()
@click.pass_context
def pem(ctx):
    """PEM encoded key format."""
    print(ctx.obj.key.to("pem"))


@to.command()
@click.pass_context
@click.option("--name", required=True, help="Username to use in PGP key.")
@click.option("--comment", default=None, help="Comment to use in PGP key.")
@click.option("--email", required=True, help="Email address to use for PGP key.")
def pgp(ctx, name, comment, email):
    """PGP key format."""
    print(ctx.obj.key.to("pgp", name=name, comment=comment, email=email))


@cli.group()
@click.pass_context
def fetch(ctx):
    """Fetch a key from somewhere.

    Examples:

        $ lokey fetch github jpf

        $ lokey fetch jwk example.okta.com

        $ lokey fetch keybase twitter:jf

        $ lokey fetch pgp joel@franusic.com

        $ lokey fetch ssh chat.shazow.net

        $ lokey fetch tls gliderlabs.com
    """
    pass


@fetch.command()
@click.pass_context
@click.argument("query")
def keybase(ctx, query):
    """Search for keys on Keybase.


    Examples:

        $ lokey fetch keybase jfranusic

        $ lokey fetch keybase twitter:jf

        $ lokey fetch keybase github:jpf
    """

    key = "usernames"
    value = query
    if ":" in query:
        (key, value) = query.split(":")

    # https://keybase.io/_/api/1.0/user/lookup.json?usernames=chris,max
    url = "https://keybase.io/_/api/1.0/user/lookup.json?{key}={value}".format(
        key=key, value=value
    )
    r = requests.get(url)
    resp = r.json()
    print(resp["them"][0]["public_keys"]["primary"]["bundle"])


@fetch.command()
@click.pass_context
@click.argument("domain_name")
def ssh(ctx, domain_name):
    """Get the public key for a SSH server.

    Example:

        $ lokey fetch ssh chat.shazow.net
    """

    class FetchKeyPolicy(paramiko.MissingHostKeyPolicy):
        def __init__(self):
            self.key = None

        def missing_host_key(self, client, hostname, key):
            self.key = key

    fetch_key_policy = FetchKeyPolicy()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(fetch_key_policy)
    try:
        client.connect(domain_name, username="lokey", timeout=5)
        key = fetch_key_policy.key.public_numbers
        key = ErisPublic(e=key.e, n=key.n)
        print(key.to("ssh"))
    except Exception as e:
        msg = ('Got "{message}" when attempting ' "to connect to {domain_name}").format(
            domain_name=domain_name, message=str(e)
        )
        raise click.ClickException(msg)


@fetch.command()
@click.pass_context
@click.argument("domain_name")
@click.option("--kid", "--key-id", type=int, help="Key ID ('kid') to print.")
def jwk(ctx, domain_name, key_id):
    """Fetch a OIDC JWK key for a domain.

    Example:

        $ lokey fetch jwk example.okta.com
    """
    url = "https://{domain_name}/.well-known/openid-configuration".format(
        domain_name=domain_name
    )
    r = requests.get(url)
    resp = r.json()
    if "jwks_uri" not in resp:
        print("Error fetching {url}".format(url=url))
    url = resp["jwks_uri"]
    r = requests.get(url)
    resp = r.json()
    keys = resp["keys"]

    if not len(keys) > 0:
        click.echo("No keys found for '{}'".format(domain_name), err=True)
        return
    if not key_id and len(keys) > 1:
        click.echo("Multiple keys found: ", err=True)
        for key in keys:
            click.echo("  - {}".format(key["kid"]), err=True)
        msg = "Printing the first key ('{}')".format(keys[0]["kid"])
        click.echo(msg, err=True)
    key_id_to_print = None
    if key_id:
        key_id_to_print = key_id
    else:
        key_id_to_print = keys[0]["kid"]
    for key in keys:
        if key["kid"] != key_id_to_print:
            continue
        print(json.dumps(key))


@fetch.command()
@click.pass_context
@click.argument("github_username")
@click.option("--key-id", type=int, help="ID of GitHub user key to print.")
def github(ctx, github_username, key_id):
    """Fetch a user key from GitHub.

    Example:

        $ lokey fetch github jpf
    """
    url = "https://api.github.com/users/{github_username}/keys".format(
        github_username=github_username
    )
    r = requests.get(url)
    keys = r.json()
    if not len(keys) > 0:
        msg = "No keys found for user '{}'".format(github_username)
        click.echo(msg, err=True)
        return
    if "message" in keys:
        msg = 'Error from GitHub: "{}"'.format(keys["message"])
        raise click.ClickException(msg)

    if not key_id and len(keys) > 1:
        click.echo("Multiple keys found: ", err=True)
        for key in keys:
            click.echo("  - {}".format(key["id"]), err=True)
        click.echo("Printing the first key ('{}')".format(keys[0]["id"]))
    key_id_to_print = None
    if key_id:
        key_id_to_print = key_id
    else:
        key_id_to_print = keys[0]["id"]
    for key in keys:
        if key["id"] != key_id_to_print:
            continue
        print(key["key"])


@fetch.command()
@click.pass_context
@click.argument("domain_name")
def tls(ctx, domain_name):
    """Get the TLS certificate for a domain.

    Example:

        $ lokey fetch tls gliderlabs.com
    """
    try:
        cert = stdlib_ssl.get_server_certificate((domain_name, 443))
        click.echo(cert)
    except:
        msg = (
            "Unable to fetch key from {}, " "is that domain configured for TLS?"
        ).format(domain_name)
        raise click.ClickException(msg)


@fetch.command()
@click.pass_context
@click.argument("search_string")
@click.option("--key-id", help="ID of PGP key to print.")
@click.option("--all", is_flag=True, default=False, help="Search all keyservers.")
@click.option("--server", help="PGP keyserver to search.")
def pgp(ctx, search_string, key_id, all, server):
    """Search for a PGP key on keyservers.

    The following keyservers are searched in order until a match is found:

    - pool.sks-keyservers.net

    - keys.gnupg.net

    - pgp.mit.edu

    - keyserver.ubuntu.com

    - zimmermann.mayfirst.org
    """

    servers = []
    if server:
        servers.append(server)
    else:
        doc = pgp.__doc__
        for line in doc.split("\n"):
            delimiter = "       - "
            if not line.startswith(delimiter):
                continue
            server = line.replace(delimiter, "")
            servers.append(server)

    for server in servers:
        addr = "http://{}".format(server)
        click.echo("Searching {}".format(addr), err=True)
        serv = KeyServer(addr)
        try:
            responses = serv.search(search_string)
        except Exception as e:
            msg = "Error from server: {}".format(e.msg)
            click.echo(msg, err=True)
            continue
        # FIXME: DRY up this bit of code with jwk code too
        keys = []
        for key in responses:
            if "RSA" in key.algo:
                keys.append(key)
        if not key_id and len(keys) > 1:
            click.echo("Multiple keys found: ", err=True)
            for key in keys:
                click.echo("  - {}".format(key.keyid), err=True)
            msg = "Printing the first key ('{}')".format(keys[0].keyid)
            click.echo(msg, err=True)
        key_id_to_print = None
        if key_id:
            key_id_to_print = key_id
        else:
            key_id_to_print = keys[0].keyid
        for key in keys:
            if key.keyid != key_id_to_print:
                continue
            print(key.key)
        if not all:
            return


if __name__ == "__main__":
    cli(obj=LokeyContext())
