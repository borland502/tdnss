import string
import unittest
import random

from tdnss import OK
from tdnss.connection import Connection


class SettingsTests(unittest.TestCase):
    def test_get_tsig_keys(self):
        c = Connection()
        c.login()

        r = c.settings_api().get_tsig_key_names()

        self.assertEqual(r.status, OK)

    def test_get_settings(self):
        c = Connection()
        c.login()

        r = c.settings_api().get_settings()

        self.assertEqual(r.status, OK)

    def test_add_remove_tsig_key(self):
        c = Connection()
        c.login()

        zone_name = f'{"".join(random.sample(string.ascii_lowercase[:26], 16))}.com'

        r = c.settings_api().add_tsig_key(zone_name)
        self.assertEqual(r.status, OK)
        self.assertIsNotNone(
            filter(lambda key: key["keyName"] == zone_name, r.data["tsigKeys"])
        )

        r = c.settings_api().rm_tsig_key(zone_name)
        self.assertEqual(r.status, OK)
        self.assertEqual(
            list(filter(lambda key: key["keyName"] == zone_name, r.data["tsigKeys"])),
            [],
        )


if __name__ == "__main__":
    unittest.main()
