import unittest
import eris
from tests.shared import ExpectedRSANumbers
from tests.shared import ExpectedKeystoreRSANumbers

class TestEris(unittest.TestCase):
    def setUp(self):
        self.key_dir = "tests/fixtures"
        self.expected = ExpectedRSANumbers()
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
        
    def test_openssh_private_key(self):
        self.read_key("rsa_1024_private.ssh")
        transmuter = eris.OpenSSHPrivate()
        self.assertHandlesPrivateKey(transmuter)

    def test_jwk_private_key(self):
        self.read_key("rsa_1024_private.jwk")
        transmuter = eris.JWKPrivate()
        self.assertHandlesPrivateKey(transmuter)

    def test_jwk_public_key(self):
        self.read_key("rsa_1024_public.jwk")
        transmuter = eris.JWKPublic()
        self.assertHandlesPublicKey(transmuter)

    def test_PEMPrivate(self):
        self.read_key("rsa_1024_private.pem")
        transmuter = eris.PEMPrivate()
        self.assertHandlesPrivateKey(transmuter)

    def test_PEMPublic(self):
        self.read_key("rsa_1024_public.pem")
        transmuter = eris.PEMPublic()
        self.assertHandlesPublicKey(transmuter)

    def test_JavaKeyStorePrivate(self):
        self.read_key("rsa_1024_keystore.jks")
        transmuter = eris.JavaKeyStorePrivate()
        self.expected = ExpectedKeystoreRSANumbers()
        self.assertHandlesPrivateKey(transmuter)

    def test_PGPPublic(self):
        self.read_key("rsa_1024_public.pgp")
        transmuter = eris.PGPPublic()
        self.assertHandlesPublicKey(transmuter)

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

