#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the semantic protocol-version contract."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
ORACLE_PATH = ROOT / "conformance/blob_stream_oracle.py"
ORACLE_SPEC = importlib.util.spec_from_file_location("blob_stream_oracle", ORACLE_PATH)
if ORACLE_SPEC is None or ORACLE_SPEC.loader is None:
    raise RuntimeError(f"cannot load {ORACLE_PATH}")
ORACLE = importlib.util.module_from_spec(ORACLE_SPEC)
ORACLE_SPEC.loader.exec_module(ORACLE)


class ProtocolVersionContractTests(unittest.TestCase):


    def test_every_profile_five_fuzz_seed_is_an_actual_decodable_record(self) -> None:
        seed_root = ROOT / "fuzz/corpus/stream_transfer_decode"
        seeds = sorted(seed_root.iterdir())
        self.assertGreaterEqual(len(seeds), 8)
        observed = set()
        transcripts = set()
        for seed in seeds:
            payload = seed.read_bytes()
            if payload.startswith(b"HEX:"):
                wire = bytes.fromhex(payload[4:].strip().decode("ascii"))
                observed.add(ORACLE.decode_stream_record(wire))
            elif payload.startswith(b"ASD1"):
                protected_len = int.from_bytes(payload[4:8], "big")
                self.assertTrue(payload[8:8 + protected_len].startswith(b"ASTRFR01"))
                native_record = payload[8 + protected_len:]
                self.assertEqual(
                    int.from_bytes(native_record[:4], "big"), len(native_record) - 4
                )
                self.assertTrue(native_record[4:].startswith(b"ASTRBS02"))
                ORACLE.inspect_native_record(native_record)
                self.assertLessEqual(len(payload), 1_050_766)
            else:
                self.assertTrue(payload.startswith(b"AST1"), seed)
                self.assertIn(payload[4], (0, 1))
                accepted = payload[4] == 1
                count = payload[5]
                offset = 6
                tags = []
                for _ in range(count):
                    length = int.from_bytes(payload[offset:offset + 4], "big")
                    offset += 4
                    tags.append(ORACLE.decode_stream_record(payload[offset:offset + length]))
                    offset += length
                self.assertEqual(offset, len(payload))
                transcripts.add((accepted, tuple(tags)))
        self.assertEqual(observed, set(range(0xd6, 0xde)))
        self.assertIn((True, (0xd6, 0xdd, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc)), transcripts)
        self.assertIn((True, (0xd6, 0xdd, 0xd7, 0xda, 0xdb, 0xdc)), transcripts)
        self.assertEqual(sum(not accepted for accepted, _ in transcripts), 4)


if __name__ == "__main__":
    unittest.main()
