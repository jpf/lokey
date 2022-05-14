import unittest
import eris
from tests.shared import ExpectedRSANumbers
from tests.shared import ExpectedKeystoreRSANumbers
import json


class TestEris(unittest.TestCase):
    def setUp(self):
        self.key_dir = "tests/fixtures"
        self.expected = ExpectedRSANumbers()
        self.eris_public = eris.ErisPublic(e=self.expected.e, n=self.expected.n)
        self.eris_private = eris.ErisPrivate(
            p=self.expected.p,
            q=self.expected.q,
            d=self.expected.d,
            dmp1=self.expected.dmp1,
            dmq1=self.expected.dmq1,
            iqmp=self.expected.iqmp,
            public_numbers=self.eris_public,
        )

        self.data = None

    def read_key(self, filename):
        with open(f"{self.key_dir}/{filename}") as f:
            self.data = f.buffer.read()

    def assertHandlesPrivateKey(self, transmuter):
        self.assertTrue(transmuter.handles(self.data))

        transmuter.deserialize(self.data)
        self.assertEquals(transmuter._d, self.expected.d)
        self.assertEquals(transmuter._p, self.expected.p)
        self.assertEquals(transmuter._q, self.expected.q)
        self.assertEquals(transmuter._dmp1, self.expected.dmp1)
        self.assertEquals(transmuter._dmq1, self.expected.dmq1)
        self.assertEquals(transmuter._iqmp, self.expected.iqmp)

    def assertHandlesPublicKey(self, transmuter):
        self.assertTrue(transmuter.handles(self.data))

        transmuter.deserialize(self.data)
        self.assertEquals(transmuter._e, self.expected.e)
        self.assertEquals(transmuter._n, self.expected.n)

    def test_openssh_public_key(self):
        self.read_key("rsa_1024_public.ssh")
        transmuter = eris.SSHPublic()
        self.assertHandlesPublicKey(transmuter)

    def test_openssh_public_key_output(self):
        obj = self.eris_public
        self.read_key("rsa_1024_public.ssh")
        want = self.data.decode().strip()
        got = obj.to("ssh", comment="joel@gibson.example")
        self.assertEqual(got, want)

    def test_openssh_public_key_fingerprint(self):
        self.read_key("rsa_1024_public.ssh")
        transmuter = eris.SSHPublic()
        transmuter.deserialize(self.data)

        want = "29:83:bd:31:a8:41:e8:3c:55:36:ce:47:59:f1:5e:7d"
        got = transmuter.fingerprint(algorithm="md5", encoding="hex")
        self.assertEqual(got, want)

        want = "ofBNOG7P0bVG5ArCfRBpWpYpud03G1EO8bovIRHXSf0"
        got = transmuter.fingerprint(algorithm="sha256", encoding="base64")
        self.assertEqual(got, want)
        got = transmuter.fingerprint()
        self.assertEqual(got, want)

    def test_openssh_private_key(self):
        self.read_key("rsa_1024_private.ssh")
        transmuter = eris.OpenSSHPrivate()
        self.assertHandlesPrivateKey(transmuter)

    @unittest.skip("Not implemented in Eris yet")
    def test_openssh_private_key_output(self):
        obj = self.eris_private
        self.read_key("rsa_1024_private.ssh")
        want = self.data.decode()
        got = obj.to("ssh")
        self.assertEqual(got, want)

    def test_jwk_public_key(self):
        self.read_key("rsa_1024_public.jwk")
        transmuter = eris.JWKPublic()
        self.assertHandlesPublicKey(transmuter)

    def test_jwk_public_key_output(self):
        obj = self.eris_public
        self.read_key("rsa_1024_public.jwk")
        want = json.loads(self.data)
        got = json.loads(obj.to("jwk"))
        self.assertEqual(got, want)

    def test_jwk_private_key(self):
        self.read_key("rsa_1024_private.jwk")
        transmuter = eris.JWKPrivate()
        self.assertHandlesPrivateKey(transmuter)

    def test_jwk_private_key_output(self):
        obj = self.eris_private
        self.read_key("rsa_1024_private.jwk")
        want = json.loads(self.data)
        got = json.loads(obj.to("jwk"))
        self.assertEqual(got, want)

    def test_PEMPublic(self):
        self.read_key("rsa_1024_public.pem")
        transmuter = eris.PEMPublic()
        self.assertHandlesPublicKey(transmuter)

    def test_PEMPublic_output(self):
        obj = self.eris_public
        self.read_key("rsa_1024_public.pem")
        want = self.data.decode().strip()
        got = obj.to("pem").strip()
        self.assertEqual(got, want)

    def test_PEMPrivate(self):
        self.read_key("rsa_1024_private.pem")
        transmuter = eris.PEMPrivate()
        self.assertHandlesPrivateKey(transmuter)

    def test_JavaKeyStorePrivate(self):
        self.read_key("rsa_1024_keystore.jks")
        transmuter = eris.JavaKeyStorePrivate()
        self.expected = ExpectedKeystoreRSANumbers()
        self.assertHandlesPrivateKey(transmuter)

    @unittest.skip("Need to write test")
    def test_PGPPublic(self):
        self.read_key("rsa_1024_public.pgp")
        transmuter = eris.PGPPublic()
        self.assertHandlesPublicKey(transmuter)
        self.assertTrue(False)

    @unittest.skip("Eris doesn't yet handle reading name, comment, or email from a key")
    def test_PGPPublic_output(self):
        obj = self.eris_public
        self.read_key("rsa_1024_public.pgp")
        want = self.data.decode().strip()
        got = obj.to("pgp", name="foo", comment="foo", email="foo")
        self.assertEqual(got, want)

    def test_PGPPrivate(self):
        self.read_key("rsa_1024_private.pgp")
        transmuter = eris.PGPPrivate()
        transmuter.password = "password"
        self.assertHandlesPrivateKey(transmuter)

    @unittest.skip
    def test_X509Public(self):
        self.assertTrue(False)

    @unittest.skip
    def test_CSRPrivate(self):
        self.assertTrue(False)
