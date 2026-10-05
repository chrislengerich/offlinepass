#!/usr/bin/env python3
"""Unit tests for passlib — no terminal required."""

import json
import os
import tempfile
import unittest

from passlib import (
    PasswordStore,
    ProtonItem,
    generate_password,
    generate_alias,
    generate_totp,
    totp_secret_from_input,
    parse_totp_uri,
)


class TestProtonItem(unittest.TestCase):
    def test_to_proton_json_round_trip(self):
        item = ProtonItem(
            name="Test Site",
            username="testuser",
            password="s3cret",
            urls=["https://test.example.com"],
            note="my note",
        )
        obj = item.to_proton_json()
        self.assertEqual(obj["data"]["type"], "login")
        self.assertEqual(obj["data"]["content"]["itemUsername"], "testuser")
        self.assertEqual(obj["data"]["content"]["password"], "s3cret")
        self.assertEqual(obj["data"]["metadata"]["name"], "Test Site")

        restored = ProtonItem.from_proton_json(obj)
        self.assertEqual(restored.name, "Test Site")
        self.assertEqual(restored.username, "testuser")
        self.assertEqual(restored.password, "s3cret")
        self.assertEqual(restored.urls, ["https://test.example.com"])
        self.assertEqual(restored.note, "my note")

    def test_identity_prefers_username(self):
        item = ProtonItem(name="X", username="ko", email="ko@mail.com")
        self.assertEqual(item.identity, "ko")

    def test_identity_falls_back_to_email(self):
        item = ProtonItem(name="X", username="", email="ko@mail.com")
        self.assertEqual(item.identity, "ko@mail.com")

    def test_matches_single_word(self):
        item = ProtonItem(name="GitHub", username="ko", urls=["https://github.com"])
        self.assertTrue(item.matches("git"))
        self.assertTrue(item.matches("ko"))
        self.assertFalse(item.matches("aws"))

    def test_matches_multiple_words_all_must_match(self):
        item = ProtonItem(name="AWS Console", email="ko@company.com", note="root")
        self.assertTrue(item.matches("aws root"))
        self.assertTrue(item.matches("aws company"))
        self.assertFalse(item.matches("aws gitlab"))

    def test_matches_case_insensitive(self):
        item = ProtonItem(name="GitHub", username="KO")
        self.assertTrue(item.matches("GITHUB"))
        self.assertTrue(item.matches("ko"))


class TestPasswordGeneration(unittest.TestCase):
    def test_default_length(self):
        pw = generate_password()
        self.assertEqual(len(pw), 24)

    def test_custom_length(self):
        pw = generate_password(32)
        self.assertEqual(len(pw), 32)

    def test_contains_expected_chars(self):
        for _ in range(50):
            pw = generate_password(50)
            self.assertTrue(any(c.isupper() for c in pw))
            self.assertTrue(any(c.islower() for c in pw))
            self.assertTrue(any(c.isdigit() for c in pw))

    def test_uniqueness(self):
        pws = {generate_password() for _ in range(100)}
        self.assertEqual(len(pws), 100)

    def test_alias_format(self):
        alias = generate_alias()
        self.assertIn("@", alias)
        self.assertGreater(len(alias), 10)


class TestTOTP(unittest.TestCase):
    # RFC 6238 test secret (base32 of "12345678901234567890")
    RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    RFC_URI = f"otpauth://totp/test?secret={RFC_SECRET}&issuer=Test&digits=8&period=30"

    def test_parse_uri(self):
        secret, issuer, digits, period = parse_totp_uri(self.RFC_URI)
        self.assertEqual(secret, self.RFC_SECRET)
        self.assertEqual(issuer, "Test")
        self.assertEqual(digits, 8)
        self.assertEqual(period, 30)

    def test_raw_secret_wrapped_to_uri(self):
        uri = totp_secret_from_input("JBSWY3DPEHPK3PXP")
        self.assertTrue(uri.startswith("otpauth://totp/"))
        secret, _, _, _ = parse_totp_uri(uri)
        self.assertEqual(secret, "JBSWY3DPEHPK3PXP")

    def test_uri_passthrough(self):
        result = totp_secret_from_input(self.RFC_URI)
        self.assertEqual(result, self.RFC_URI)

    def test_rfc6238_vectors(self):
        """Verify against RFC 6238 Appendix B test vectors (SHA1, 8 digits)."""
        # time, expected_code
        vectors = [
            (59,          "94287082"),
            (1111111109,  "07081804"),
            (1111111111,  "14050471"),
            (1234567890,  "89005924"),
            (2000000000,  "69279037"),
        ]
        for t, expected in vectors:
            code, remaining = generate_totp(self.RFC_URI, at_time=t)
            self.assertEqual(code, expected, f"Failed at t={t}")

    def test_remaining_within_period(self):
        code, remaining = generate_totp(self.RFC_URI, at_time=100)
        self.assertGreater(remaining, 0)
        self.assertLessEqual(remaining, 30)

    def test_code_changes_across_periods(self):
        code1, _ = generate_totp(self.RFC_URI, at_time=0)
        code2, _ = generate_totp(self.RFC_URI, at_time=30)
        self.assertNotEqual(code1, code2)

    def test_same_code_within_period(self):
        code1, _ = generate_totp(self.RFC_URI, at_time=10)
        code2, _ = generate_totp(self.RFC_URI, at_time=20)
        self.assertEqual(code1, code2)


class TestDisplayName(unittest.TestCase):
    def test_uses_name_when_set(self):
        item = ProtonItem(name="GitHub", username="ko", urls=["https://github.com"])
        self.assertEqual(item.display_name, "GitHub")

    def test_derives_from_url(self):
        item = ProtonItem(name="", username="ko", urls=["https://gitlab.com"])
        self.assertEqual(item.display_name, "gitlab.com")

    def test_falls_back_to_username(self):
        item = ProtonItem(name="", username="ko", urls=[])
        self.assertEqual(item.display_name, "ko")

    def test_falls_back_to_email(self):
        item = ProtonItem(name="", username="", email="ko@mail.com", urls=[])
        self.assertEqual(item.display_name, "ko@mail.com")


class TestPasswordStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        )
        self.tmp.close()
        self.store = PasswordStore(self.tmp.name, use_gpg=False)

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_load_nonexistent_returns_empty(self):
        store = PasswordStore("/nonexistent/path.json", use_gpg=False)
        self.assertEqual(store.load(), [])

    def test_load_test_data(self):
        here = os.path.dirname(os.path.abspath(__file__))
        store = PasswordStore(os.path.join(here, "test_data.json"), use_gpg=False)
        items = store.load()
        self.assertEqual(len(items), 5)
        names = [it.name for it in items]
        self.assertIn("GitHub", names)
        self.assertIn("AWS Console", names)

    def test_sorted_alphabetically(self):
        here = os.path.dirname(os.path.abspath(__file__))
        store = PasswordStore(os.path.join(here, "test_data.json"), use_gpg=False)
        items = store.load()
        names = [it.name.lower() for it in items]
        self.assertEqual(names, sorted(names))

    def test_round_trip_save_load(self):
        items = [
            ProtonItem(name="Zulu", username="z", password="pw1"),
            ProtonItem(name="Alpha", username="a", password="pw2"),
        ]
        self.store.save(items)
        loaded = self.store.load()
        self.assertEqual(len(loaded), 2)
        self.assertEqual(loaded[0].name, "Alpha")
        self.assertEqual(loaded[1].name, "Zulu")
        self.assertEqual(loaded[0].password, "pw2")

    def test_parse_single_item(self):
        with open(self.tmp.name, "w") as f:
            json.dump(
                ProtonItem(name="Solo", username="s", password="p").to_proton_json(),
                f,
            )
        items = self.store.load()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].name, "Solo")

    def test_parse_list_of_items(self):
        with open(self.tmp.name, "w") as f:
            json.dump([
                ProtonItem(name="A", password="1").to_proton_json(),
                ProtonItem(name="B", password="2").to_proton_json(),
            ], f)
        items = self.store.load()
        self.assertEqual(len(items), 2)

    def test_envelope_has_vault_structure(self):
        self.store.save([ProtonItem(name="X", password="p")])
        with open(self.tmp.name) as f:
            data = json.load(f)
        self.assertIn("vaults", data)
        self.assertIn("local", data["vaults"])
        self.assertEqual(len(data["vaults"]["local"]["items"]), 1)

    def test_rev_bumps_per_save(self):
        self.store.save([ProtonItem(name="X", password="p")])
        with open(self.tmp.name) as f:
            rev1 = json.load(f)["rev"]
        self.store.save([ProtonItem(name="X", password="p")])
        with open(self.tmp.name) as f:
            rev2 = json.load(f)["rev"]
        self.assertEqual(rev2, rev1 + 1)

    def test_device_id_stable(self):
        self.store.save([ProtonItem(name="X", password="p")])
        with open(self.tmp.name) as f:
            d1 = json.load(f)["deviceId"]
        self.assertTrue(d1)
        self.store.save([ProtonItem(name="Y", password="p")])
        with open(self.tmp.name) as f:
            d2 = json.load(f)["deviceId"]
        self.assertEqual(d1, d2)

    def test_unknown_fields_preserved(self):
        with open(self.tmp.name, "w") as f:
            json.dump({"vaults": {"local": {"items": [], "customMarker": "keep"}}}, f)
        self.store.load()
        self.store.save([ProtonItem(name="X", password="p")])
        with open(self.tmp.name) as f:
            data = json.load(f)
        self.assertEqual(data["vaults"]["local"]["customMarker"], "keep")

    def test_tombstones_survive_desktop_save(self):
        # The phone tombstoned u-B: items lack it, the envelope records it.
        with open(self.tmp.name, "w") as f:
            json.dump({
                "rev": 7,
                "deletedItemUuids": ["u-B"],
                "vaults": {"local": {"items": [
                    ProtonItem(name="A", password="1", item_uuid="u-A").to_proton_json(),
                ]}},
            }, f)
        items = self.store.load()
        self.assertEqual([i.name for i in items], ["A"])
        self.store.save(items)
        with open(self.tmp.name) as f:
            data = json.load(f)
        self.assertEqual(data["rev"], 8)
        self.assertIn("u-B", data["deletedItemUuids"])
        self.assertNotIn("u-B", [i.get("data", {}).get("metadata", {}).get("itemUuid", "")
                                 for i in data["vaults"]["local"]["items"]])


class TestProtonPassCompat(unittest.TestCase):
    """Verify the JSON format matches what the Android ProtonPassParser expects."""

    def test_item_has_required_fields(self):
        obj = ProtonItem(name="T", username="u", password="pw").to_proton_json()
        data = obj["data"]
        self.assertEqual(data["type"], "login")
        self.assertIn("metadata", data)
        self.assertIn("content", data)
        content = data["content"]
        self.assertIn("itemUsername", content)
        self.assertIn("itemEmail", content)
        self.assertIn("password", content)
        self.assertIn("urls", content)
        self.assertIn("totpUri", content)
        self.assertIn("passkeys", content)

    def test_parser_handles_data_wrapper(self):
        obj = ProtonItem(name="T", username="u", password="pw").to_proton_json()
        item = ProtonItem.from_proton_json(obj)
        self.assertEqual(item.username, "u")
        self.assertEqual(item.password, "pw")

    def test_parser_handles_bare_content(self):
        bare = {
            "content": {
                "itemUsername": "bare_user",
                "itemEmail": "",
                "password": "bare_pw",
            },
            "metadata": {"name": "Bare"},
        }
        item = ProtonItem.from_proton_json(bare)
        self.assertEqual(item.username, "bare_user")
        self.assertEqual(item.password, "bare_pw")


if __name__ == "__main__":
    unittest.main()
