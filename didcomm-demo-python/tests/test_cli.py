import json

import pytest
from click.testing import CliRunner
from peerdid.peer_did import is_peer_did

from didcomm_demo.didcomm_cli import set_secrets_resolver, cli
from didcomm_demo.secrets.secrets_resolver_demo import SecretsResolverDemo


@pytest.fixture()
def secrets_resolver(tmp_path):
    tmp_file = tmp_path / "secrets.json"
    secrets_resolver = SecretsResolverDemo(tmp_file)
    set_secrets_resolver(secrets_resolver)
    return secrets_resolver


@pytest.mark.parametrize(
    "auth_keys_count_param",
    [
        pytest.param('', id="no-params"),
        pytest.param('--auth_keys_count=1', id="1-auth-key"),
    ]
)
def test_create_peer_did_numalg_0(secrets_resolver, auth_keys_count_param):
    runner = CliRunner()
    args = ['create-peer-did']
    if auth_keys_count_param:
        args.append(auth_keys_count_param)
    result = runner.invoke(cli, args)
    assert result.exit_code == 0
    peer_did = result.output.strip()
    assert is_peer_did(peer_did)
    assert peer_did.startswith("did:peer:0")
    assert len(secrets_resolver.get_kids()) == 1
    assert secrets_resolver.get_kids()[0].startswith(peer_did)


@pytest.mark.parametrize(
    "auth_keys_count,agreement_keys_count",
    [
        pytest.param(1, 1, id="1auth-1agreem"),
        pytest.param(2, 3, id="2auth-3agreem"),
        pytest.param(0, 1, id="0auth-1agreem"),
        pytest.param(0, 2, id="0auth-2agreem")
    ]
)
def test_create_peer_did_numalg_2_no_service(secrets_resolver, auth_keys_count, agreement_keys_count):
    runner = CliRunner()
    result = runner.invoke(cli, ['create-peer-did', f'--auth_keys_count={auth_keys_count}',
                                 f'--agreement_keys_count={agreement_keys_count}'])
    assert result.exit_code == 0
    peer_did = result.output.strip()
    assert is_peer_did(peer_did)
    assert peer_did.startswith("did:peer:2")
    assert len(secrets_resolver.get_kids()) == auth_keys_count + agreement_keys_count
    for kid in secrets_resolver.get_kids():
        assert kid.startswith(peer_did)


def test_create_peer_did_numalg_2_with_service_endpoint_no_routing(secrets_resolver):
    runner = CliRunner()
    result = runner.invoke(cli, ['create-peer-did',
                                 '--auth_keys_count=1',
                                 '--agreement_keys_count=1',
                                 '--service_endpoint="https://my-endpoint'])
    assert result.exit_code == 0
    peer_did = result.output.strip()
    assert is_peer_did(peer_did)
    assert peer_did.startswith("did:peer:2")
    assert len(secrets_resolver.get_kids()) == 2
    for kid in secrets_resolver.get_kids():
        assert kid.startswith(peer_did)


def test_resolve_peer_did(secrets_resolver):
    did = "did:peer:0z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V"
    runner = CliRunner()
    result = runner.invoke(cli, ['resolve-peer-did', did])
    assert result.exit_code == 0
    did_doc_json = result.output.strip()
    did_doc = json.loads(did_doc_json)
    assert "authentication" in did_doc
    assert did_doc["id"] == did