import unittest

from src.remediation import remediate_storage_config


class TestRemediation(unittest.TestCase):

    def test_public_access_is_disabled(self):
        config = {
            "resource": "test-storage",
            "public_access": True,
        }

        result = remediate_storage_config(config)

        self.assertFalse(result["public_access"])
        self.assertEqual(result["status"], "REMEDIATED")

    def test_secure_config_stays_secure(self):
        config = {
            "resource": "test-storage",
            "public_access": False,
        }

        result = remediate_storage_config(config)

        self.assertFalse(result["public_access"])
        self.assertEqual(result["status"], "SECURE")

    def test_original_config_is_unchanged(self):
        config = {
            "resource": "test-storage",
            "public_access": True,
        }

        remediate_storage_config(config)

        self.assertTrue(config["public_access"])


if __name__ == "__main__":
    unittest.main()
