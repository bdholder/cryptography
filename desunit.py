import unittest
import des


def vector_generator(open_file):
    for line in open_file:
        if line.startswith('#'):
            continue

        params = line.split()
        for i, v in enumerate(params):
            params[i] = bytes.fromhex(v)

        yield params


class BlackBoxTestDES(unittest.TestCase):

    def __init__(self, methodName='runTest'):
        super().__init__(methodName)
        self.cipher = des.DES()

    def test_DES_vectors(self):
        with open('DES_test_vectors.txt') as f:
            for key, ptext, ctext in vector_generator(f):
                with self.subTest(key=key, ptext=ptext, ctext=ctext):
                    self.cipher.load_key(key)
                    self.assertEqual(self.cipher.encrypt(ptext), ctext)
                    self.assertEqual(self.cipher.decrypt(ctext), ptext)
    
    def test_DES_iteration_vectors(self):
        with open('DES_iteration_vectors.txt') as f:
            for key, ptext, ctext1, ctext100, ctext1000 in vector_generator(f):
                with self.subTest(key=key, ptext=ptext, ctext1=ctext1,
                                  ctext100=ctext100, ctext1000=ctext1000):
                    self.cipher.load_key(key)
                    self.assertEqual(self.cipher.encrypt(ptext), ctext1)
                    self.assertEqual(self.cipher.decrypt(ctext1), ptext)
                    
                    for i in range(100):
                        ptext = self.cipher.encrypt(ptext)
                    self.assertEqual(ptext, ctext100)

                    for i in range(900):
                        ptext = self.cipher.encrypt(ptext)
                    self.assertEqual(ptext, ctext1000)


class BlackBoxTestTDES(unittest.TestCase):
    
    def __init__(self, methodName='runTest'):
        super().__init__(methodName)
        self.cipher = des.TDES()

    def test_TDES_vectors(self):
        with open('TDES_test_vectors.txt') as f:
            for key, ptext, ctext in vector_generator(f):
                with self.subTest(key=key, ptext=ptext, ctext=ctext):
                    self.cipher.load_key(key)
                    self.assertEqual(self.cipher.encrypt(ptext), ctext)
                    self.assertEqual(self.cipher.decrypt(ctext), ptext)

if __name__ == '__main__':
    unittest.main()
