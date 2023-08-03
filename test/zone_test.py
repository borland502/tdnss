import unittest

from tdnss import OK
from tdnss.connection import Connection


class ZoneTests(unittest.TestCase):
    def test_create_and_delete_zone(self):
        connection = Connection()
        r = connection.login()
        self.assertEqual(r.status, OK)

        r = connection.zone_api().create_zone("example.com")
        self.assertEqual(r.status, OK)
        # self.assertEqual(zone.data[0], "example.com")

        r = connection.zone_api().delete_zone("example.com")
        self.assertEqual(r.status, OK)


if __name__ == '__main__':
    unittest.main()
