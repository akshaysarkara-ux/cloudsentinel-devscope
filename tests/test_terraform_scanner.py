import tempfile
import unittest
from pathlib import Path

from src.terraform_scanner import scan_terraform_file


class TestTerraformScanner(unittest.TestCase):

    def test_scanner_detects_public_access(self):
        terraform_code = '''
resource "aws_s3_bucket_public_access_block" "example" {
  bucket                  = "example-bucket"
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
'''

        with tempfile.TemporaryDirectory() as temp_dir:
            terraform_file = Path(temp_dir) / "test_bucket.tf"
            terraform_file.write_text(terraform_code, encoding="utf-8")

            findings = scan_terraform_file(str(terraform_file))

        self.assertTrue(
            any(
                finding.get("rule_id") == "PUBLIC_ACCESS"
                for finding in findings
            ),
            "The scanner should detect insecure public-access settings."
        )


if __name__ == "__main__":
    unittest.main()