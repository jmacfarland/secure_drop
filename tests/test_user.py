import unittest
from user import User

class RegisterTest(unittest.TestCase):
    def setUp(self):
        self.u = User()
        self.u.register("Rocky Rococco", "r.roc@gmail.com")

    def test_get_name(self):
        self.assertEqual(self.u.get_name(),"Rocky Rococco")

    def test_get_email(self):
        self.assertEqual(self.u.get_email(), "r.roc@gmail.com")

    def test_dict(self):
        self.assertEqual(repr(self.u), '{"fullname": "Rocky Rococco", "email": "r.roc@gmail.com"}')

    def test_file_io(self):
        self.u.save_to_file('test_rocky.txt')
        u2 = User()
        u2.load_from_file('test_rocky.txt')
        self.assertEqual(self.u.get_name(), u2.get_name())
        self.assertEqual(self.u.get_email(), u2.get_email())
