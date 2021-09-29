import asyncio
from typing import Optional, List

from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import DID, JSON
from didcomm.core.utils import id_generator_default
from didcomm.message import Message
from didcomm.pack_encrypted import pack_encrypted, PackEncryptedResult, PackEncryptedConfig
from didcomm.unpack import unpack, UnpackResult
from peerdid import peer_did
from peerdid.types import DIDDocVerMaterialFormat

from didcomm_demo.core.peer_did_creator import PeerDIDCreator
from didcomm_demo.did_doc.did_resolver_peer_did import DIDResolverPeerDID
from didcomm_demo.secrets.secrets_resolver_demo import SecretsResolverDemo
from didcomm_demo.secrets.secrets_resolver_editable import SecretsResolverEditable


class DIDCommDemo:

    def __init__(self, secrets_resolver: Optional[SecretsResolverEditable] = None) -> None:
        self.secrets_resolver = secrets_resolver or SecretsResolverDemo()
        self.resolvers_config = ResolversConfig(
            secrets_resolver=self.secrets_resolver,
            did_resolver=DIDResolverPeerDID()
        )

    def create_peer_did(self,
                        auth_keys_count: int = 1,
                        agreement_keys_count: int = 0,
                        service_endpoint: Optional[str] = None,
                        service_routing_keys: Optional[List[str]] = None) -> DID:
        return PeerDIDCreator(secrets_resolver=self.secrets_resolver).create_peer_did(
            auth_keys_count=auth_keys_count,
            agreement_keys_count=agreement_keys_count,
            service_endpoint=service_endpoint,
            service_routing_keys=service_routing_keys
        )

    @staticmethod
    def resolve_peer_did(did: DID, format: DIDDocVerMaterialFormat) -> JSON:
        return peer_did.resolve_peer_did(did, format=format)

    def pack(self, msg: str, to: str, frm: Optional[str] = None, sign_frm: Optional[str] = None,
             config: Optional[PackEncryptedConfig] = None) -> PackEncryptedResult:
        message = Message(
            body={"msg": msg},
            id=id_generator_default(),
            type="my-protocol/1.0",
            frm=frm,
            to=[to],
        )
        config = config or PackEncryptedConfig()
        config.forward = False  # until it's support in all languages
        return asyncio.get_event_loop().run_until_complete(
            pack_encrypted(
                resolvers_config=self.resolvers_config,
                message=message,
                frm=frm,
                to=to,
                sign_frm=sign_frm,
                pack_config=config
            )
        )

    def unpack(self, packed_msg: str) -> (str, UnpackResult):
        res = asyncio.get_event_loop().run_until_complete(
            unpack(
                resolvers_config=self.resolvers_config,
                packed_msg=packed_msg
            )
        )
        msg = res.message.body["msg"]
        return msg, res
