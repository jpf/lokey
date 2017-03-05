# lokey

lokey is a tool that makes it easy to work with and convert between cryptographic key formats.

Named after the shape shifting and mischief-making Trickster from Norse mythology, this tool serves to test the bounds of possibilities and order.

## Installing lokey

The fastest way to get lokey is to use [pip](https://en.wikipedia.org/wiki/Pip_(package_manager)):

    $ pip install lokey

## Using lokey

lokey makes it easy to fetch cryptographic keys from public sources like [Keybase](https://keybase.io/) and [PGP keyservers](https://en.wikipedia.org/wiki/Key_server_%28cryptographic%29), for example:

Fetch my Keybase key using [my Twitter handle](https://twitter.com/jf):

    $ lokey fetch keybase twitter:jf

Search for PGP keys from journalists at the New York Times:

    $ lokey fetch pgp nytimes.com

You can see all of the fetching commands that lokey has by typing:

    $ lokey fetch

lokey is also a tool for converting between cryptographic key formats, for example

Make it easier to grant your friends access to your SSH server:

    $ sudo adduser jf
    $ mkdir ~jf/.ssh
    $ lokey fetch keybase twitter:jf | lokey to ssh > ~jf/.ssh/authorized_keys

Send an S/MIME encrypted email to an administrator of a TLS secured webserver:

    $ echo "A ship journeys from the east, Muspell's people are coming" > message.txt
    $ lokey fetch tls example.com > example.com.pem
    $ openssl smime -encrypt -des3 -in message.txt example.com.pem > smime.p7m

One of the administrators of the TLS secured webserver could read the message using this command:

    openssl smime -decrypt -in smime.p7m -passin pass:[password for key] -inkey /path/to/webserver.key

lokey will also give you information about keys that you pipe into it:

    $ cat ~/.ssh/id_rsa.pub | lokey

At the moment, lokey can convert RSA keys between the following
formats: openssh, X.509  Certificates, PGP, and JWT.

With lokey you can:
-   Use the public SSL certificate of a website to send an S/MIME
    encrypted email to any website owner that uses TLS:
-   Grant access to your a server by turning your friend's keybase key
    into an openssh key

## Inspiration

Many things inspired this project. 
The genesis of this project comes from the many conversations I had with my dad about his implementation of [OpenPGP in Common Lisp](https://github.com/pfranusic/BlackLight).
One of those conversations was when I first learned that all RSA keys derived from the numbers ("e", "n", "d").
My dad's paper "[Why RSA Works](https://github.com/pfranusic/why-RSA-works/blob/master/why-RSA-works.pdf)", gave me the grounding I needed to reason and understand RSA cryptography.

Other inspirations include [Zed Shaw's vulnarb.com](https://web.archive.org/web/20110828210530/http://vulnarb.com/) project, which was the first time I considered using TLS certificates for encrypting email.
[The Monkeysphere Project](http://web.monkeysphere.info/) which inspired me to think of using the PGP [web of trust](https://en.wikipedia.org/wiki/Web_of_trust) for something other than email.  

My work at Okta on [key pinning](https://github.com/okta/okta-openvpn/blob/a8868879cd74db1737a13fe34c68aa5ac20f5ebe/okta_openvpn.py#L66-L94) introduced me to Python's outstanding cryptographic library "[cryptography](https://cryptography.io/en/latest/)". 
And most recently, my work on [converting JWK formatted keys to PEM formatted keys](https://github.com/jpf/okta-jwks-to-pem) proved how useful a command line utility for key conversion could be.

## Learn more

    $ lokey --help
    $ lokey fetch
    $ lokey to
