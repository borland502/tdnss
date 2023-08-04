import string
import unittest
import random

from tdnss import OK
from tdnss.connection import Connection
from tdnss.zone_api import RFC2136Options


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

    def test_enable_allow_zone_updates(self):
        zone_name = f'test-{"".join(random.sample(string.ascii_lowercase[:26], 16))}.com'

        connection = Connection()
        r = connection.login()
        self.assertEqual(r.status, OK)

        r = connection.zone_api().create_zone(zone_name)
        self.assertEqual(r.status, OK)

        r = connection.settings_api().add_tsig_key(zone_name)
        self.assertEqual(r.status, OK)

        r = connection.zone_api().set_zone_options(zone_name,
                                                   update_policy=RFC2136Options.Allow,
                                                   update_tsig_key_name=zone_name)
        self.assertEqual(r.status, OK)

if __name__ == '__main__':
    unittest.main()
