import unittest

from check import package_paths, validate_payload


class PackageListing(unittest.TestCase):
    def test_windows_listing_is_validated_as_archive_paths(self):
        cases = (
            ('rax', 'Cargo.toml\r\nLICENSE\r\nTHIRD_PARTY_NOTICES.md\r\n'
                    'src\\lib.rs\r\nsrc\\isa\\x86_64\\mod.rs\r\n',
             ['Cargo.toml', 'LICENSE', 'THIRD_PARTY_NOTICES.md',
              'src/lib.rs', 'src/isa/x86_64/mod.rs']),
            ('rax-capi', 'LICENSE\nTHIRD_PARTY_NOTICES.md\nbuild.rs\n'
                         'include\\rax.h\ntests\\consumer\\CMakeLists.txt\n',
             ['LICENSE', 'THIRD_PARTY_NOTICES.md', 'build.rs',
              'include/rax.h', 'tests/consumer/CMakeLists.txt']),
        )
        for package, listing, expected in cases:
            with self.subTest(package=package):
                # Cargo's native separators are not archive-member paths.
                with self.assertRaisesRegex(ValueError, 'unexpected package files'):
                    validate_payload(package, listing.splitlines())
                paths = package_paths(listing, '\\')
                self.assertEqual(paths, expected)
                validate_payload(package, paths)

    def test_normalization_keeps_boundary_rejections(self):
        listing = 'LICENSE\nTHIRD_PARTY_NOTICES.md\nsrc\\..\\secret.rs\ndocs\\notes.md\n'
        with self.assertRaisesRegex(ValueError, r"'docs/notes.md', 'src/../secret.rs'"):
            validate_payload('rax', package_paths(listing, '\\'))

    def test_posix_listing_is_unchanged(self):
        listing = 'LICENSE\nTHIRD_PARTY_NOTICES.md\nsrc/lib.rs\n'
        self.assertEqual(package_paths(listing, '/'), listing.splitlines())


if __name__ == '__main__':
    unittest.main()
