import json
from typing import Optional, List

import base58
from authlib.common.encoding import urlsafe_b64decode, to_bytes
from authlib.jose import OKPKey
from didcomm.common.types import DID
from peerdid import peer_did
from peerdid.types import DIDDocVerMaterialFormat, PublicKeyTypeAgreement, EncodingType, PublicKeyAgreement, \
    PublicKeyAuthentication, PublicKeyTypeAuthentication

from didcomm_demo.core.utils import jwk_to_secret
from didcomm_demo.secrets.secrets_resolver_editable import SecretsResolverEditable


class PeerDIDCreator:

    def __init__(self, secrets_resolver: SecretsResolverEditable) -> None:
        self.secrets_resolver = secrets_resolver

        self.auth_private_keys_jwk = []
        self.auth_public_keys_peer_did = []
        self.agreem_private_keys_jwk = []
        self.agreem_public_keys_peer_did = []
        self.service = None
        self.did = ""

    def create_peer_did(self,
                        auth_keys_count: int = 1,
                        agreement_keys_count: int = 0,
                        service_endpoint: Optional[str] = None,
                        service_routing_keys: Optional[List[str]] = None) -> DID:
        self._generate_keys(auth_keys_count=auth_keys_count, agreement_keys_count=agreement_keys_count)
        self._generate_service(service_endpoint=service_endpoint, service_routing_keys=service_routing_keys)
        self._create_peer_did()
        self._save_keys()
        return self.did

    def _generate_keys(self, auth_keys_count: int, agreement_keys_count: int):
        # generate auth keys
        for i in range(auth_keys_count):
            private_key_jwk_dict, public_key_jwk_dict = _generate_ed25519_key()
            auth_public_key_peer_did = _jwk_ed25519_to_peer_did_auth_key(public_key_jwk_dict)
            self.auth_private_keys_jwk.append(private_key_jwk_dict)
            self.auth_public_keys_peer_did.append(auth_public_key_peer_did)

        # generate agreement keys
        for i in range(agreement_keys_count):
            private_key_jwk_dict, public_key_jwk_dict = _generate_x25519_key()
            agreem_public_key_peer_did = _jwk_x25519_to_peer_did_agreement_key(public_key_jwk_dict)
            self.agreem_private_keys_jwk.append(private_key_jwk_dict)
            self.agreem_public_keys_peer_did.append(agreem_public_key_peer_did)

    def _generate_service(self, service_endpoint: Optional[str] = None,
                          service_routing_keys: Optional[List[str]] = None):
        if service_endpoint is None:
            return
        service_dict = {
            "type": "DIDCommMessaging",
            "serviceEndpoint": service_endpoint,
            "accept": ["didcomm/v2"]
        }
        if service_routing_keys:
            service_dict["routingKeys"] = service_routing_keys
        self.service = json.dumps(service_dict)

    def _create_peer_did(self):
        # if we have just one key (auth), then use numalg0 algorithm
        # otherwise use numalg2 algorithm
        if len(self.auth_public_keys_peer_did) == 1 and not self.agreem_public_keys_peer_did and not self.service:
            self.did = peer_did.create_peer_did_numalgo_0(self.auth_public_keys_peer_did[0])
        else:
            self.did = peer_did.create_peer_did_numalgo_2(
                encryption_keys=self.agreem_public_keys_peer_did,
                signing_keys=self.auth_public_keys_peer_did,
                service=self.service,
            )

    def _save_keys(self):
        # update private key kids
        _assign_kid_auth_keys(self.auth_private_keys_jwk, self.did)
        _assign_kid_agreement_keys(self.agreem_private_keys_jwk, self.did)

        # save private keys in the secrets resolver
        for key in self.auth_private_keys_jwk:
            secret = jwk_to_secret(key)
            self.secrets_resolver.add_key(secret)
        for key in self.agreem_private_keys_jwk:
            secret = jwk_to_secret(key)
            self.secrets_resolver.add_key(secret)


def _generate_ed25519_key():
    key = OKPKey.generate_key('Ed25519', is_private=True)
    private_key_jwk_dict = key.as_dict(is_private=True)
    public_key_jwk_dict = key.as_dict()
    return private_key_jwk_dict, public_key_jwk_dict


def _generate_x25519_key():
    key = OKPKey.generate_key('X25519', is_private=True)
    private_key_jwk_dict = key.as_dict(is_private=True)
    public_key_jwk_dict = key.as_dict()
    return private_key_jwk_dict, public_key_jwk_dict


def _jwk_ed25519_to_peer_did_auth_key(public_key_jwk_dict):
    x_raw = urlsafe_b64decode(to_bytes(public_key_jwk_dict["x"]))
    x_base58 = base58.b58encode(x_raw).decode()
    return PublicKeyAuthentication(
        encoding_type=EncodingType.BASE58,
        encoded_value=x_base58,
        type=PublicKeyTypeAuthentication.ED25519
    )


def _jwk_x25519_to_peer_did_agreement_key(public_key_jwk_dict):
    x_raw = urlsafe_b64decode(to_bytes(public_key_jwk_dict["x"]))
    x_base58 = base58.b58encode(x_raw).decode()
    return PublicKeyAgreement(
        encoding_type=EncodingType.BASE58,
        encoded_value=x_base58,
        type=PublicKeyTypeAgreement.X25519
    )


def _assign_kid_auth_keys(auth_private_keys_jwk, did):
    _assign_kid_private_keys(auth_private_keys_jwk, did, "authentication")


def _assign_kid_agreement_keys(agreem_private_keys_jwk, did):
    _assign_kid_private_keys(agreem_private_keys_jwk, did, "keyAgreement")


def _assign_kid_private_keys(private_keys_jwk, did, field):
    if not private_keys_jwk:
        return
    did_doc_json = peer_did.resolve_peer_did(did, format=DIDDocVerMaterialFormat.JWK)
    did_doc = json.loads(did_doc_json)
    auth_public_keys = did_doc.get(field, [])
    if len(private_keys_jwk) != len(auth_public_keys):
        raise ValueError("Invalid peer DID")
    for private_key, public_key in zip(private_keys_jwk, auth_public_keys):
        private_key["kid"] = public_key["id"]
