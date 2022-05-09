import json
import inspect

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import (
    hashes,
    serialization)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import base64
import six
import struct
from pgpy.constants import (
    PubKeyAlgorithm,
    KeyFlags,
    HashAlgorithm,
    SymmetricKeyAlgorithm,
    CompressionAlgorithm)
from pgpy.packet.fields import (
    RSAPub,
    MPI,
    RSAPriv)
from pgpy.packet.packets import (
    PubKeyV4,
    PrivKeyV4)
import pgpy

import jks

transmuters = {}


def transmuter(cls):
    cls_name = cls.__name__
    transmuters[cls_name] = cls
    return cls


class CanTransmute(object):
    def to(self, obj, *args, **kwargs):
        obj = obj.upper() + self.key_type
        if obj in transmuters:
            transmuter = self
            transmuter.__class__ = transmuters[obj]
            return transmuter.serialize(*args, **kwargs)
        print("Did not find: " + obj)

    def handles(self, sample):
        return False

    def fingerprint(self):
        return False

    def __str__(self):
        docstring = inspect.getdoc(self)
        if not docstring:
            docstring = str(self.__class__) + "\n"
        out = docstring + "\n"
        numbers = ['e', 'n', 'd', 'p', 'q', 'd', 'dmp1', 'dmq1', 'iqmp']
        for number_name in numbers:
            attr = "_" + number_name
            value = getattr(self, attr, False)
            if not value:
                continue
            out += ("\t{}: {}\n".format(number_name, value))
        return out


class ErisPublic(CanTransmute, rsa.RSAPublicNumbers):
    def __init__(self, e=None, n=None):
        self.key_type = 'Public'
        # Allow empty objects:
        if e and n:
            super(ErisPublic, self).__init__(e, n)


class ErisPrivate(CanTransmute, rsa.RSAPrivateNumbers):
    def __init__(self,
                 p=None,
                 q=None,
                 d=None,
                 dmp1=None,
                 dmq1=None,
                 iqmp=None,
                 public_numbers=None):
        self.key_type = 'Private'
        self.password = None
        # Allow for empty objects:
        if p and q and d and dmp1 and dmq1 and iqmp and public_numbers:
            super(ErisPrivate, self).__init__(p,
                                              q,
                                              d,
                                              dmp1,
                                              dmq1,
                                              iqmp,
                                              public_numbers)

def intarr2long(arr):
    return int(''.join(["%02x" % byte for byte in arr]), 16)


def base64_to_long(data):
    if isinstance(data, six.text_type):
        data = data.encode("ascii")

    # urlsafe_b64decode will happily convert b64encoded data
    _d = base64.urlsafe_b64decode(bytes(data) + b'==')
    return intarr2long(struct.unpack('%sB' % len(_d), _d))

def long2intarr(long_int):
    _bytes = []
    while long_int:
        long_int, r = divmod(long_int, 256)
        _bytes.insert(0, r)
    return _bytes


def long_to_base64(n):
    bys = long2intarr(n)
    data = struct.pack('%sB' % len(bys), *bys)
    if not len(data):
        data = '\x00'
    s = base64.urlsafe_b64encode(data).rstrip(b'=')
    return s.decode("ascii")

@transmuter
class JWKPublic(ErisPublic):
    '''Public JSON Web Key (RFC7517)'''
    def __init__(self, *args, **kwargs):
        super(JWKPublic, self).__init__(args, kwargs)

    def serialize(self):
        json_payload = {
            'e': long_to_base64(self._e),
            'kty': 'RSA',
            'n': long_to_base64(self._n)}
        jwk_payload = json.dumps(json_payload)
        return jwk_payload

    def deserialize(self, data):
        jwk = json.loads(data)
        self._e = base64_to_long(jwk['e'])
        self._n = base64_to_long(jwk['n'])

    def handles(self, sample):
        sample = sample.decode('utf-8')
        if '{' in sample and '"' in sample:
            data = json.loads(sample)
            return ('e' in data) and ('n' in data) and ('d' not in data)


@transmuter
class SSHPublic(ErisPublic):
    '''Public OpenSSH Key'''
    def __init__(self, *args, **kwargs):
        super(SSHPublic, self).__init__(args, kwargs)

    def serialize(self, comment=None):
        rsa_pub = self.public_key(default_backend())
        value = (rsa_pub.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH)
        )
        if comment:
            value += " " + comment
        return value.decode()

    def deserialize(self, data):
        key = serialization.load_ssh_public_key(data, default_backend())
        self._e = key.public_numbers().e
        self._n = key.public_numbers().n

    def handles(self, sample):
        return sample.startswith(b'ssh-rsa ')


@transmuter
class OpenSSHPrivate(ErisPrivate):
    '''Private Key in OpenSSH format'''
    def __init__(self, *args, **kwargs):
        super(OpenSSHPrivate, self).__init__(args, kwargs)

    def deserialize(self, data):
        password = None
        key = serialization.load_ssh_private_key(data, password)
        private_numbers = key.private_numbers()
        self._d = private_numbers._d
        self._p = private_numbers._p
        self._q = private_numbers._q
        self._iqmp = private_numbers._iqmp
        self._dmp1 = private_numbers._dmp1
        self._dmq1 = private_numbers._dmq1
        self._public_numbers = private_numbers._public_numbers

    def handles(self, sample):
        return sample.startswith(b'-----BEGIN OPENSSH PRIVATE KEY')


class SamplePublic(ErisPublic):
    '''Example Class'''
    def __init__(self, *args, **kwargs):
        super(SamplePublic, self).__init__(args, kwargs)

    def serialize(self):
        pass

    def deserialize(self, data):
        pass

    def handles(self, sample):
        return False


@transmuter
class PGPPublic(ErisPublic):
    '''Public PGP Key'''
    def __init__(self, *args, **kwargs):
        super(PGPPublic, self).__init__(args, kwargs)

    def serialize(self, name, comment, email):
        rsa_pub = RSAPub()
        rsa_pub.e = MPI(self._e)
        rsa_pub.n = MPI(self._n)

        pub_key_v4 = PubKeyV4()
        pub_key_v4.pkalg = PubKeyAlgorithm.RSAEncryptOrSign
        pub_key_v4.keymaterial = rsa_pub
        pub_key_v4.update_hlen()

        pgp_key = pgpy.PGPKey()
        pgp_key._key = pub_key_v4

        uid = pgpy.PGPUID.new(
            name,
            comment=comment,
            email=email)
        uid._parent = pgp_key

        pgp_key._uids.append(uid)
        return str(pgp_key)

    def deserialize(self, data):
        pgp_key, _ = pgpy.PGPKey.from_blob(data)
        key_material = pgp_key._key.keymaterial
        self._e = key_material.e
        self._n = key_material.n

    def handles(self, sample):
        return sample.startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK')


@transmuter
class X509Public(ErisPublic):
    '''Public Key from an X.509 Certificate'''
    def __init__(self, *args, **kwargs):
        super(X509Public, self).__init__(args, kwargs)

    def serialize(self):
        msg = ("Creating X.509 certificates is not supported.\n"
               "Try creating a csr with a private key instead: \n"
               "    'cat your-private-key | lokey to csr'")
        return(msg)

    def deserialize(self, data):
        cert = x509.load_pem_x509_certificate(data, default_backend())
        key_material = cert.public_key().public_numbers()
        self._e = key_material.e
        self._n = key_material.n

    def handles(self, sample):
        return sample.startswith(b'-----BEGIN CERT')


# SMIME: CN=First Last/emailAddress=first.last@example.com
# SSL: CN=www.example.com

@transmuter
class CSRPrivate(ErisPrivate):
    '''Certificate Signing Request'''
    def __init__(self, *args, **kwargs):
        super(CSRPrivate, self).__init__(args, kwargs)

    def serialize(self,
                  # password=None,
                  country=u"US",
                  state=u"CA",
                  city=u"San Francisco",
                  company=u"Lokey Examle",
                  common_name=u"example.com"):
        # This should be handled already
        # if not password:
        #     password = None
        key = serialization.load_pem_private_key(
            self.to('pem'),
            password=None,
            backend=default_backend())

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, city),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, company),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        cert = x509.CertificateSigningRequestBuilder().subject_name(
            subject
        ).sign(key, hashes.SHA256(), default_backend())
        return cert.public_bytes(serialization.Encoding.PEM)


@transmuter
class PEMPublic(ErisPublic):
    '''Public Key in PEM format'''
    def __init__(self, *args, **kwargs):
        super(PEMPublic, self).__init__(args, kwargs)

    def serialize(self):
        rsa_pub = self.public_key(default_backend())
        formatted = rsa_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return(str(formatted, "utf-8"))

    def deserialize(self, data):
        key = serialization.load_pem_public_key(data, default_backend())
        self._e = key.public_numbers().e
        self._n = key.public_numbers().n

    def handles(self, sample):
        return sample.startswith(b'-----BEGIN PUBLIC KEY')


@transmuter
class JWKPrivate(ErisPrivate):
    '''Private JSON Web Key (RFC7517)'''
    numbers = [
            ('e', 'e'),
            ('d', 'd'),
            ('n', 'n'),
            ('q', 'q'),
            ('p', 'p'),
            ('qi', 'iqmp'),
            ('dq', 'dmq1'),
            ('dp', 'dmp1')]

    def __init__(self, *args, **kwargs):
        super(JWKPrivate, self).__init__(args, kwargs)

    def serialize(self):
        json_payload = {}
        self._e = self._public_numbers._e
        self._n = self._public_numbers._n
        for key, number in self.numbers:
            json_payload[key] = long_to_base64(getattr(self, '_' + number))
        return (
            '{{'
            '"e": "{e}", '
            '"d": "{d}", '
            '"n": "{n}", '
            '"q": "{q}", '
            '"p": "{p}", '
            '"qi": "{qi}", '
            '"dq": "{dq}", '
            '"dp": "{dp}", '
            '"kty": "RSA"}}').format(**json_payload)

    def deserialize(self, data):
        jwk = json.loads(data)
        for key, number in self.numbers:
            if key in ['e', 'n']:
                continue
            setattr(self, '_' + number, base64_to_long(jwk[key]))
        e = base64_to_long(jwk['e'])
        n = base64_to_long(jwk['n'])
        self._public_numbers = ErisPublic(e=e, n=n)

    def handles(self, sample):
        sample = sample.decode('utf-8')
        if '{' in sample and '"' in sample:
            data = json.loads(sample)
            return ('e' in data) and ('n' in data) and ('d' in data)


@transmuter
class PEMPrivate(ErisPrivate):
    '''Private Key in PEM format'''
    def __init__(self, *args, **kwargs):
        super(PEMPrivate, self).__init__(args, kwargs)

    def serialize(self):
        # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/#serialization-formats
        rsa_pub = self.private_key(default_backend())
        encryption_algorithm = serialization.NoEncryption()
        if self.password:
            encryption_algorithm = serialization.BestAvailableEncryption(
                bytes(self.password))
        formatted = rsa_pub.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption_algorithm)
        return(str(formatted, "utf-8"))

    def deserialize(self, data):
        # data = str.encode(data)
        rsa_priv = serialization.load_pem_private_key(
            data, self.password, default_backend()
        )
        private_numbers = rsa_priv.private_numbers()
        self._d = private_numbers._d
        self._p = private_numbers._p
        self._q = private_numbers._q
        self._iqmp = private_numbers._iqmp
        self._dmp1 = private_numbers._dmp1
        self._dmq1 = private_numbers._dmq1
        self._public_numbers = private_numbers._public_numbers

    def handles(self, sample):
        return sample.startswith(b'-----BEGIN RSA PRIVATE KEY')


@transmuter
class JavaKeyStorePrivate(ErisPrivate):
    '''Private Key in Java Keystore (JKS) format'''
    def __init__(self, *args, **kwargs):
        super(JavaKeyStorePrivate, self).__init__(args, kwargs)

    def serialize(self):
        pass

    def deserialize(self, data):
        ks = jks.KeyStore.loads(data, "password")
        # if any of the keys in the store use a password that is not the same as the store password:
        # ks.entries["key1"].decrypt("key_password")

        keys = list(ks.private_keys.items())

        if len(keys) == 0:
            raise ValueError("No private keys found in JKS")
        alias, private_key = keys[0]

        if private_key.algorithm_oid != jks.util.RSA_ENCRYPTION_OID:
            raise ValueError(
                f"Unsupported JKS algorithm: {private_key.algorithm_oid}"
            )

        # print(f"Private key: {alias}")
        rsa_priv = serialization.load_der_private_key(
            private_key.pkey, self.password, default_backend()
        )
        private_numbers = rsa_priv.private_numbers()
        self._d = private_numbers._d
        self._p = private_numbers._p
        self._q = private_numbers._q
        self._iqmp = private_numbers._iqmp
        self._dmp1 = private_numbers._dmp1
        self._dmq1 = private_numbers._dmq1
        self._public_numbers = private_numbers._public_numbers

    def handles(self, sample):
        return sample.startswith(b'\xfe\xed\xfe\xed')


@transmuter
class PGPPrivate(ErisPrivate):
    '''Private PGP Key'''
    def __init__(self, *args, **kwargs):
        super(PGPPrivate, self).__init__(args, kwargs)

    def deserialize(self, data):
        pgp_key, _ = pgpy.PGPKey.from_blob(data)
        password = ""
        if self.password:
            password = self.password
        with pgp_key.unlock(password):
            key_material = pgp_key._key.keymaterial
            # https://tools.ietf.org/html/rfc4880#section-5.5.3
            # "multiprecision integer (MPI) of RSA secret exponent d."
            self._d = key_material.d
            # "MPI of RSA secret prime value p."
            self._p = key_material.p
            # "MPI of RSA secret prime value q (p < q)."
            self._q = key_material.q
            self._iqmp = rsa.rsa_crt_iqmp(key_material.p, key_material.q)
            self._dmp1 = rsa.rsa_crt_dmp1(key_material.d, key_material.p)
            self._dmq1 = rsa.rsa_crt_dmq1(key_material.d, key_material.q)
            self._public_numbers = ErisPublic(
                e=key_material.e,
                n=key_material.n)

    def serialize(self, name, comment, email):
        rsa_priv = RSAPriv()
        rsa_priv.e = MPI(self.public_numbers._e)
        rsa_priv.n = MPI(self.public_numbers._n)
        rsa_priv.d = MPI(self._d)
        rsa_priv.p = MPI(self._p)
        rsa_priv.q = MPI(self._q)
        # https://github.com/SecurityInnovation/PGPy/blob/f08afed730816e71eafa0dd59ce77d8859ce24b5/pgpy/packet/fields.py#L1116
        rsa_priv.u = MPI(rsa.rsa_crt_iqmp(self._q, self._p))
        rsa_priv._compute_chksum()

        pub_key_v4 = PrivKeyV4()
        pub_key_v4.pkalg = PubKeyAlgorithm.RSAEncryptOrSign
        pub_key_v4.keymaterial = rsa_priv
        pub_key_v4.update_hlen()

        pgp_key = pgpy.PGPKey()
        pgp_key._key = pub_key_v4

        uid = pgpy.PGPUID.new(name, comment=comment, email=email)

        # FIXME: Should I add a "Signature" Packet?
        # FIXME: Should I add subkeys?

        pgp_key.add_uid(
            uid,
            usage={
                KeyFlags.Sign,
                KeyFlags.EncryptCommunications,
                KeyFlags.EncryptStorage},
            hashes=[
                HashAlgorithm.SHA256,
                HashAlgorithm.SHA384,
                HashAlgorithm.SHA512,
                HashAlgorithm.SHA224],
            ciphers=[
                SymmetricKeyAlgorithm.AES256,
                SymmetricKeyAlgorithm.AES192,
                SymmetricKeyAlgorithm.AES128],
            compression=[
                CompressionAlgorithm.ZLIB,
                CompressionAlgorithm.BZ2,
                CompressionAlgorithm.ZIP,
                CompressionAlgorithm.Uncompressed])

        if self.password:
            pgp_key.protect(
                self.password,
                SymmetricKeyAlgorithm.AES256,
                HashAlgorithm.SHA256)

        return str(pgp_key)

    def handles(self, sample):
        return sample.startswith(b'-----BEGIN PGP PRIVATE KEY BLOCK')


def load(f, password=None):
    cls = None
    mebibyte_in_bytes = 1048576
    data = f.buffer.read(mebibyte_in_bytes)
    for transmuter in transmuters.values():
        # print(transmuter)
        try:
            if transmuter().handles(data):
                cls = transmuter()
        except:
            # FIXME: Catch specific errors here
            pass
    if password:
        cls.password = password
    if cls:
        # print(f"Using cls: {cls}")
        cls.deserialize(data)
        return cls
    else:
        msg = ("Input is not recognized. "
               "Got this on input:\n\n{}").format(data)
        raise ValueError(msg)
