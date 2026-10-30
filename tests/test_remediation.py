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
        self.assertTrue(result["verification_passed"])

    def test_original_config_is_preserved(self):
        config = {
            "resource": "test-storage",
            "public_access": True,
        }

        result = remediate_storage_config(config)

        self.assertTrue(config["public_access"])
        self.assertTrue(result["original_config"]["public_access"])

    def test_change_is_recorded(self):
        config = {
            "resource": "test-storage",
            "public_access": True,
        }

        result = remediate_storage_config(config)

        self.assertEqual(len(result["changes"]), 1)
        self.assertEqual(
            result["changes"][0]["setting"],
            "public_access"
        )

    def test_already_secure_configuration(self):
        config = {
            "resource": "test-storage",
            "public_access": False,
        }

        result = remediate_storage_config(config)

        self.assertEqual(result["status"], "SECURE")
        self.assertTrue(result["verification_passed"])
        self.assertEqual(result["changes"], [])

    def test_missing_public_access_setting(self):
        config = {
            "resource": "test-storage",
        }

        result = remediate_storage_config(config)

        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertFalse(result["verification_passed"])


if __name__ == "__main__":
    unittest.main()