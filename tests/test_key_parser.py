#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright: (c) 2025, Gonzalo Alvarez

import pytest
from typing import List, Optional

from secureenclave.datamodel import GpgKey, GpgSubkey
from secureenclave.key_parser import _dedup_keys, _parse_gpg_list_cmd


# Helper functions (moved from test_gpg.py)
def create_subkey(
    key_id: str,
    secret_available: bool,
    algorithm_name: str = "RSA",
    key_length: int = 2048,
    creation_date: int = 0,
    expiration_date: Optional[int] = None,
    capabilities: Optional[List[str]] = None,
    fingerprint: Optional[str] = None,
    keygrip: Optional[str] = None
) -> GpgSubkey:
    if capabilities is None:
        capabilities = ['s']
    if fingerprint is None:
        fingerprint = f"fpr_sub_{key_id}"
    if keygrip is None:
        keygrip = f"grp_sub_{key_id}"
    return GpgSubkey(
        key_id=key_id,
        algorithm_name=algorithm_name, key_length=key_length, creation_date=creation_date,
        expiration_date=expiration_date, capabilities=capabilities, fingerprint=fingerprint,
        keygrip=keygrip, secret_available=secret_available
    )


def create_key(
    key_id: str,
    uid: str,
    secret_available: bool,
    subkeys: Optional[List[GpgSubkey]] = None,
    uid_validity: str = "f",
    algorithm_name: str = "RSA",
    key_length: int = 4096,
    creation_date: int = 0,
    expiration_date: Optional[int] = None,
    owner_trust: str = "u",
    capabilities: Optional[List[str]] = None,
    fingerprint: Optional[str] = None,
    keygrip: Optional[str] = None
) -> GpgKey:
    if subkeys is None:
        subkeys = []
    if capabilities is None:
        capabilities = ['c']
    if fingerprint is None:
        fingerprint = f"fpr_main_{key_id}"
    if keygrip is None:
        keygrip = f"grp_main_{key_id}"
    return GpgKey(
        uid=uid, uid_validity=uid_validity, key_id=key_id,
        algorithm_name=algorithm_name, key_length=key_length, creation_date=creation_date,
        expiration_date=expiration_date, owner_trust=owner_trust, capabilities=capabilities,
        fingerprint=fingerprint, keygrip=keygrip, secret_available=secret_available,
        subkeys=subkeys
    )


# Tests for _dedup_keys (moved from test_gpg.py)
def test_dedup_keys_empty_lists():
    """Test _dedup_keys with empty public and secret key lists."""
    public_keys = []
    secret_keys = []
    result = _dedup_keys(public_keys, secret_keys)
    assert result == []


def test_dedup_keys_only_public_keys():
    """Test _dedup_keys with only public keys."""
    pub_key1 = create_key(key_id="pub1", uid="user1@example.com", secret_available=False)
    public_keys = [pub_key1]
    secret_keys = []
    result = _dedup_keys(public_keys, secret_keys)
    assert len(result) == 1
    assert result[0].key_id == "pub1"
    assert result[0].uid == "user1@example.com"
    assert not result[0].secret_available


def test_dedup_keys_only_secret_keys():
    """Test _dedup_keys with only secret keys."""
    sec_key1 = create_key(key_id="sec1", uid="user2@example.com", secret_available=True)
    public_keys = []
    secret_keys = [sec_key1]
    result = _dedup_keys(public_keys, secret_keys)
    assert len(result) == 1
    assert result[0].key_id == "sec1"
    assert result[0].uid == "user2@example.com"
    assert result[0].secret_available


def test_dedup_keys_public_and_secret_no_overlap():
    """Test _dedup_keys with non-overlapping public and secret keys."""
    pub_key1 = create_key(key_id="pub1", uid="user1@example.com", secret_available=False)
    sec_key1 = create_key(key_id="sec1", uid="user2@example.com", secret_available=True)
    public_keys = [pub_key1]
    secret_keys = [sec_key1]
    result = _dedup_keys(public_keys, secret_keys)
    assert len(result) == 2
    key_ids = {key.key_id for key in result}
    assert "pub1" in key_ids
    assert "sec1" in key_ids


def test_dedup_keys_overlap_secret_takes_precedence_for_primary_key():
    """Test that secret key's 'secret_available' status takes precedence for the primary key."""
    shared_id = "shared_key"
    shared_uid = "shared@example.com"
    pub_key = create_key(key_id=shared_id, uid=shared_uid, secret_available=False)
    sec_key = create_key(key_id=shared_id, uid=shared_uid, secret_available=True)
    public_keys = [pub_key]
    secret_keys = [sec_key]
    result = _dedup_keys(public_keys, secret_keys)
    assert len(result) == 1
    merged_key = result[0]
    assert merged_key.key_id == shared_id
    assert merged_key.uid == shared_uid
    assert merged_key.secret_available


def test_dedup_keys_overlap_subkeys_merge_secret_status():
    """Test merging of subkeys, prioritizing secret key's 'secret_available' status."""
    shared_id = "key_with_subkeys"
    shared_uid = "subkeys@example.com"
    subkey1_id = "subkey1"
    subkey2_id = "subkey2"

    pub_subkey1 = create_subkey(key_id=subkey1_id, secret_available=False)
    pub_subkey2 = create_subkey(key_id=subkey2_id, secret_available=False)
    sec_subkey1 = create_subkey(key_id=subkey1_id, secret_available=True)

    pub_key = create_key(key_id=shared_id, uid=shared_uid, secret_available=False, subkeys=[pub_subkey1, pub_subkey2])
    sec_key = create_key(key_id=shared_id, uid=shared_uid, secret_available=True, subkeys=[sec_subkey1])

    public_keys = [pub_key]
    secret_keys = [sec_key]
    result = _dedup_keys(public_keys, secret_keys)

    assert len(result) == 1
    merged_key = result[0]
    assert merged_key.secret_available
    assert len(merged_key.subkeys) == 2

    subkeys_map = {sk.key_id: sk for sk in merged_key.subkeys}
    assert subkeys_map[subkey1_id].secret_available
    assert not subkeys_map[subkey2_id].secret_available


def test_dedup_keys_secret_key_has_new_subkey_not_in_public():
    """Test when secret key introduces a new subkey not present in public key's version."""
    shared_id = "key_new_subkey_in_secret"
    shared_uid = "newsubkey@example.com"
    pub_only_subkey_id = "pub_subkey"
    sec_only_subkey_id = "sec_subkey"

    pub_skey = create_subkey(key_id=pub_only_subkey_id, secret_available=False)
    sec_skey = create_subkey(key_id=sec_only_subkey_id, secret_available=True)

    pub_key = create_key(key_id=shared_id, uid=shared_uid, secret_available=False, subkeys=[pub_skey])
    sec_key = create_key(key_id=shared_id, uid=shared_uid, secret_available=True, subkeys=[sec_skey])

    public_keys = [pub_key]
    secret_keys = [sec_key]
    result = _dedup_keys(public_keys, secret_keys)

    assert len(result) == 1
    merged_key = result[0]
    assert merged_key.secret_available
    assert len(merged_key.subkeys) == 2

    subkeys_map = {sk.key_id: sk for sk in merged_key.subkeys}
    assert pub_only_subkey_id in subkeys_map
    assert not subkeys_map[pub_only_subkey_id].secret_available
    assert sec_only_subkey_id in subkeys_map
    assert subkeys_map[sec_only_subkey_id].secret_available


def test_dedup_keys_public_key_has_subkey_not_in_secret():
    """Test when public key has a subkey not mentioned in the secret key's version."""
    shared_id = "key_pub_has_extra_subkey"
    shared_uid = "pubextrasub@example.com"
    common_subkey_id = "common_subkey"
    pub_only_subkey_id = "pub_only_subkey"

    common_pub_skey = create_subkey(key_id=common_subkey_id, secret_available=False)
    pub_only_skey = create_subkey(key_id=pub_only_subkey_id, secret_available=False)
    common_sec_skey = create_subkey(key_id=common_subkey_id, secret_available=True)

    pub_key = create_key(key_id=shared_id, uid=shared_uid, secret_available=False, subkeys=[common_pub_skey, pub_only_skey])
    sec_key = create_key(key_id=shared_id, uid=shared_uid, secret_available=True, subkeys=[common_sec_skey])

    public_keys = [pub_key]
    secret_keys = [sec_key]
    result = _dedup_keys(public_keys, secret_keys)

    assert len(result) == 1
    merged_key = result[0]
    assert merged_key.secret_available
    assert len(merged_key.subkeys) == 2

    subkeys_map = {sk.key_id: sk for sk in merged_key.subkeys}
    assert common_subkey_id in subkeys_map
    assert subkeys_map[common_subkey_id].secret_available
    assert pub_only_subkey_id in subkeys_map
    assert not subkeys_map[pub_only_subkey_id].secret_available


def test_dedup_keys_different_uids_same_keyid_treated_as_distinct():
    """Test that keys with the same key_id but different UIDs are treated as distinct keys."""
    same_key_id = "same_key"
    uid1 = "user1@example.com"
    uid2 = "user2@example.com"

    key_uid1 = create_key(key_id=same_key_id, uid=uid1, secret_available=False)
    key_uid2 = create_key(key_id=same_key_id, uid=uid2, secret_available=False)

    public_keys = [key_uid1, key_uid2]
    secret_keys = []
    result = _dedup_keys(public_keys, secret_keys)

    assert len(result) == 2
    uids_in_result = {key.uid for key in result}
    key_ids_in_result = {key.key_id for key in result}
    assert uid1 in uids_in_result
    assert uid2 in uids_in_result
    assert len(key_ids_in_result) == 1
    assert same_key_id in key_ids_in_result


def test_dedup_keys_complex_merge_scenario():
    """Test a more complex scenario involving multiple keys and subkey merging rules."""
    pub_k1 = create_key("k1", "uid1@test.com", False, [create_subkey("sk1_1", False), create_subkey("sk1_2", False)])
    pub_k2 = create_key("k2", "uid2@test.com", False, [create_subkey("sk2_1", False)])
    pub_k3 = create_key("k3", "uid3@test.com", False, [])

    sec_k1 = create_key("k1", "uid1@test.com", True, [create_subkey("sk1_1", True), create_subkey("sk1_3", True)])
    sec_k4 = create_key("k4", "uid4@test.com", True, [create_subkey("sk4_1", True)])

    public_keys = [pub_k1, pub_k2, pub_k3]
    secret_keys = [sec_k1, sec_k4]

    result = _dedup_keys(public_keys, secret_keys)
    assert len(result) == 4

    result_map = {(k.key_id, k.uid): k for k in result}

    merged_k1 = result_map[("k1", "uid1@test.com")]
    assert merged_k1.secret_available
    assert len(merged_k1.subkeys) == 3
    sk_map_k1 = {sk.key_id: sk for sk in merged_k1.subkeys}
    assert sk_map_k1["sk1_1"].secret_available
    assert not sk_map_k1["sk1_2"].secret_available
    assert sk_map_k1["sk1_3"].secret_available

    merged_k2 = result_map[("k2", "uid2@test.com")]
    assert not merged_k2.secret_available
    assert len(merged_k2.subkeys) == 1
    assert not merged_k2.subkeys[0].secret_available
    assert merged_k2.subkeys[0].key_id == "sk2_1"

    merged_k3 = result_map[("k3", "uid3@test.com")]
    assert not merged_k3.secret_available
    assert len(merged_k3.subkeys) == 0

    merged_k4 = result_map[("k4", "uid4@test.com")]
    assert merged_k4.secret_available
    assert len(merged_k4.subkeys) == 1
    assert merged_k4.subkeys[0].secret_available
    assert merged_k4.subkeys[0].key_id == "sk4_1"

# TODO: Add tests for _parse_gpg_list_cmd here
# For example:
# def test_parse_gpg_list_cmd_empty_output():
#     assert _parse_gpg_list_cmd("") == []
#
# def test_parse_gpg_list_cmd_single_key_no_subkeys():
#     raw_output = """
# trd:1:1719000000:1609459200:3:
# pub:u:4096:1:AABBCCDD11223344:1609459200:1700000000::u:::scESC:
# fpr:::::::::AABBCCDD11223344AABBCCDD11223344AABBCCDD:
# grp:::::::::GGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPP:
# uid:u::::1609459200::Description <email@example.com>:
# """
#     keys = _parse_gpg_list_cmd(raw_output)
#     assert len(keys) == 1
#     # Add more assertions for key properties
