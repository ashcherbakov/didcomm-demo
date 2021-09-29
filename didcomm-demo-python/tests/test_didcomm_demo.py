import json

import pytest
from didcomm.pack_encrypted import PackEncryptedConfig
from peerdid.peer_did import is_peer_did
from peerdid.types import DIDDocVerMaterialFormat

from didcomm_demo.didcomm_demo import DIDCommDemo
from didcomm_demo.secrets.secrets_resolver_demo import SecretsResolverDemo


@pytest.fixture()
def secrets_resolver(tmp_path):
    tmp_file = tmp_path / "secrets.json"
    return SecretsResolverDemo(tmp_file)


@pytest.fixture()
def demo(secrets_resolver):
    return DIDCommDemo(secrets_resolver)


def check_expected_did_doc(did, auth_keys_count, agreement_keys_count, service_endpoint=None,
                           service_routing_keys=None):
    did_doc = json.loads(DIDCommDemo.resolve_peer_did(did, format=DIDDocVerMaterialFormat.JWK))
    assert len(did_doc.get("authentication", [])) == auth_keys_count
    assert len(did_doc.get("keyAgreement", [])) == agreement_keys_count
    if service_endpoint is None:
        assert "service" not in did_doc
    else:
        assert did_doc.get("service")[0]["serviceEndpoint"] == service_endpoint
        assert did_doc.get("service")[0]["accept"] == ["didcomm/v2"]
        if service_routing_keys is not None:
            assert did_doc.get("service")[0]["routingKeys"] == service_routing_keys


def test_create_peer_did_numalg_0_default(demo):
    did = demo.create_peer_did()
    assert is_peer_did(did)
    assert did.startswith("did:peer:0")
    assert len(demo.secrets_resolver.get_kids()) == 1
    assert demo.secrets_resolver.get_kids()[0].startswith(did)
    check_expected_did_doc(did, auth_keys_count=1, agreement_keys_count=0, service_endpoint=None)


def test_create_peer_did_numalg_0_one_auth_key(demo):
    did = demo.create_peer_did(auth_keys_count=1)
    assert is_peer_did(did)
    assert did.startswith("did:peer:0")
    assert len(demo.secrets_resolver.get_kids()) == 1
    assert demo.secrets_resolver.get_kids()[0].startswith(did)
    check_expected_did_doc(did, auth_keys_count=1, agreement_keys_count=0, service_endpoint=None)


@pytest.mark.parametrize(
    "auth_keys_count,agreement_keys_count",
    [
        pytest.param(1, 1, id="1auth-1agreem"),
        pytest.param(2, 3, id="2auth-3agreem"),
        pytest.param(0, 1, id="0auth-1agreem"),
        pytest.param(0, 2, id="0auth-2agreem")
    ]
)
def test_create_peer_did_numalg_2_no_service(demo, auth_keys_count, agreement_keys_count):
    did = demo.create_peer_did(auth_keys_count=auth_keys_count, agreement_keys_count=agreement_keys_count)
    assert is_peer_did(did)
    assert did.startswith("did:peer:2")
    assert len(demo.secrets_resolver.get_kids()) == auth_keys_count + agreement_keys_count
    for kid in demo.secrets_resolver.get_kids():
        assert kid.startswith(did)
    check_expected_did_doc(did,
                           auth_keys_count=auth_keys_count, agreement_keys_count=agreement_keys_count,
                           service_endpoint=None)


def test_create_peer_did_numalg_2_with_service_endpoint_no_routing(demo):
    endpoint = "https://my-endpoint"
    did = demo.create_peer_did(auth_keys_count=1, agreement_keys_count=1, service_endpoint=endpoint)
    assert is_peer_did(did)
    assert did.startswith("did:peer:2")
    assert len(demo.secrets_resolver.get_kids()) == 2
    for kid in demo.secrets_resolver.get_kids():
        assert kid.startswith(did)
    check_expected_did_doc(did,
                           auth_keys_count=1, agreement_keys_count=1,
                           service_endpoint=endpoint, service_routing_keys=None)


def test_create_peer_did_numalg_2_with_service_endpoint_and_routing(demo):
    endpoint = "https://my-endpoint"
    routing_keys = ["key1", "key2"]
    did = demo.create_peer_did(auth_keys_count=1, agreement_keys_count=1,
                               service_endpoint=endpoint,
                               service_routing_keys=routing_keys)
    assert is_peer_did(did)
    assert did.startswith("did:peer:2")
    assert len(demo.secrets_resolver.get_kids()) == 2
    for kid in demo.secrets_resolver.get_kids():
        assert kid.startswith(did)
    check_expected_did_doc(did,
                           auth_keys_count=1, agreement_keys_count=1,
                           service_endpoint=endpoint, service_routing_keys=routing_keys)


def test_resolve_peer_did():
    did = "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
    did_doc_json = DIDCommDemo.resolve_peer_did(did, format=DIDDocVerMaterialFormat.JWK)
    did_doc = json.loads(did_doc_json)
    assert "authentication" in did_doc
    assert did_doc["id"] == did


@pytest.fixture()
def did_frm(demo):
    return demo.create_peer_did(auth_keys_count=2, agreement_keys_count=2)


@pytest.fixture()
def did_to(demo):
    return demo.create_peer_did(auth_keys_count=2, agreement_keys_count=2)


@pytest.mark.parametrize("input_msg", ["hello"])
def test_pack_unpack_authcrypt(input_msg, demo, did_frm, did_to):
    packed_res = demo.pack(
        msg=input_msg,
        frm=did_frm,
        to=did_to
    )

    unpacked_msg, unpack_res = demo.unpack(packed_res.packed_msg)
    assert input_msg == unpacked_msg
    assert unpack_res.metadata.authenticated is True
    assert unpack_res.metadata.encrypted is True
    assert unpack_res.metadata.anonymous_sender is False
    assert unpack_res.metadata.non_repudiation is False


@pytest.mark.parametrize("input_msg", ["hello"])
def test_pack_anoncrypt(input_msg, demo, did_to):
    packed_res = demo.pack(
        msg=input_msg,
        to=did_to
    )

    unpacked_msg, unpack_res = demo.unpack(packed_res.packed_msg)
    assert input_msg == unpacked_msg
    assert unpack_res.metadata.authenticated is False
    assert unpack_res.metadata.encrypted is True
    assert unpack_res.metadata.anonymous_sender is True
    assert unpack_res.metadata.non_repudiation is False


@pytest.mark.parametrize("input_msg", ["hello"])
def test_pack_authcrypt_signed(input_msg, demo, did_frm, did_to):
    packed_res = demo.pack(
        msg=input_msg,
        frm=did_frm,
        to=did_to,
        sign_frm=did_frm
    )

    unpacked_msg, unpack_res = demo.unpack(packed_res.packed_msg)
    assert input_msg == unpacked_msg
    assert unpack_res.metadata.authenticated is True
    assert unpack_res.metadata.encrypted is True
    assert unpack_res.metadata.anonymous_sender is False
    assert unpack_res.metadata.non_repudiation is True


@pytest.mark.parametrize("input_msg", ["hello"])
def test_pack_authcrypt_protect_sender(input_msg, demo, did_frm, did_to):
    config = PackEncryptedConfig(protect_sender_id=True)
    packed_res = demo.pack(
        msg=input_msg,
        frm=did_frm,
        to=did_to,
        config=config
    )

    unpacked_msg, unpack_res = demo.unpack(packed_res.packed_msg)
    assert input_msg == unpacked_msg
    assert unpack_res.metadata.authenticated is True
    assert unpack_res.metadata.encrypted is True
    assert unpack_res.metadata.anonymous_sender is True
    assert unpack_res.metadata.non_repudiation is False
