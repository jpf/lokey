# lokey

lokey a tool to convert between different cryptographic key formats.

At the moment, lokey can convert RSA keys between the following
formats: openssh, X.509  Certificates, PGP, and JWT.

With lokey you can:
-   Use the public SSL certicate of a website to send an S/MIME
    encrypted email to any website owner that uses TLS:
-   Grant access to your a server by turning your friend's keybase key
    into an openssh key

Named after the shape shifting and mischief-making Trickster from Norse mythology, this tool serves to test the bounds of possiblities and order.

## Install

    pip install lokey

## Learn more

    lokey --help