"""Fixed compiler-data/cache/transport controls; no upstream code execution."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import urllib.error
import prepare

class CompilerInputTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / 'project/ethereum/test/chain-registry'
        self.root.mkdir(parents=True)
        self.data = b'fixed inert compiler-input test data'
        self.digest = hashlib.sha256(self.data).hexdigest()
        self.target = self.root / 'evidence/soljson.cjs'
        self.cache = self.root.parents[2] / 'research/registry-ed25519/evidence/soljson.cjs'
        for patcher in [patch.object(prepare, 'ROOT', self.root), patch.object(prepare, 'DIGEST', self.digest)]:
            patcher.start()
            self.addCleanup(patcher.stop)

    def response(self, data):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = data
        return response

    def test_existing_verified_file_never_fetches(self):
        self.target.parent.mkdir(parents=True)
        self.target.write_bytes(self.data)
        with patch.object(prepare.urllib.request, 'urlopen', side_effect=AssertionError('unexpected fetch')):
            prepare.main()
        self.assertEqual(self.target.read_bytes(), self.data)

    def test_verified_local_cache_is_copied(self):
        self.cache.parent.mkdir(parents=True)
        self.cache.write_bytes(self.data)
        with patch.object(prepare.urllib.request, 'urlopen', side_effect=AssertionError('unexpected fetch')):
            prepare.main()
        self.assertEqual(self.target.read_bytes(), self.data)

    def test_fixed_download_replaces_unverified_data(self):
        self.target.parent.mkdir(parents=True)
        self.target.write_bytes(b'unverified')
        self.cache.parent.mkdir(parents=True)
        self.cache.write_bytes(b'unverified')
        response = self.response(self.data)
        with patch.object(prepare.urllib.request, 'urlopen', return_value=response) as fetch:
            prepare.main()
            fetch.assert_called_once_with(prepare.URL, timeout=60)
        response.__enter__.return_value.read.assert_called_once_with(16777217)
        self.assertEqual(self.target.read_bytes(), self.data)

    def test_digest_and_size_refusal_preserve_existing_file(self):
        self.target.parent.mkdir(parents=True)
        self.target.write_bytes(b'unverified')
        for body in [b'wrong digest', b'0' * 16777217]:
            with self.subTest(size=len(body)), patch.object(prepare.urllib.request, 'urlopen', return_value=self.response(body)):
                with self.assertRaises(ValueError):
                    prepare.main()
            self.assertEqual(self.target.read_bytes(), b'unverified')

    def test_transport_failure_never_creates_a_compiler(self):
        with patch.object(prepare.urllib.request, 'urlopen', side_effect=urllib.error.URLError('fixed unit refusal')):
            with self.assertRaises(urllib.error.URLError):
                prepare.main()
        self.assertFalse(self.target.exists())

if __name__ == '__main__':
    unittest.main(verbosity=2)
