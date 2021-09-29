import json
from typing import Optional

from didcomm.common.types import DID, VerificationMethodType, VerificationMaterial, VerificationMaterialFormat, \
    DIDDocServiceTypes
from didcomm.did_doc.did_doc import DIDDoc, VerificationMethod, DIDCommService
from didcomm.did_doc.did_resolver import DIDResolver
from peerdid import peer_did
from peerdid.types import DIDDocVerMaterialFormat


class DIDResolverPeerDID(DIDResolver):

    async def resolve(self, did: DID) -> Optional[DIDDoc]:
        # request DID Doc in JWK format
        did_doc_json = peer_did.resolve_peer_did(did, format=DIDDocVerMaterialFormat.JWK)
        did_doc = json.loads(did_doc_json)

        key_agreements = did_doc.get("keyAgreement", [])
        authentications = did_doc.get("authentication", [])

        return DIDDoc(
            did=did,
            key_agreement_kids=[ka["id"] for ka in key_agreements],
            authentication_kids=[a["id"] for a in authentications],
            verification_methods=[
                self._get_verification_method(m) for m in authentications + key_agreements
            ],
            didcomm_services=list(filter(
                None,
                [
                    self._get_service(s) for s in did_doc.get("service", [])
                ]
            ))
        )

    @classmethod
    def _get_verification_method(cls, method: dict):
        # assume JWK requested
        return VerificationMethod(
            id=method["id"],
            type=VerificationMethodType.JSON_WEB_KEY_2020,
            controller=method["controller"],
            verification_material=VerificationMaterial(
                format=VerificationMaterialFormat.JWK,
                value=json.dumps(method["publicKeyJwk"])
            )
        )

    @classmethod
    def _get_service(cls, service: dict) -> Optional[DIDCommService]:
        service_type = service["type"]
        if service_type != DIDDocServiceTypes.DID_COMM_MESSAGING.value:
            return None
        return DIDCommService(
            id=service["id"],
            service_endpoint=service["serviceEndpoint"],
            routing_keys=service.get("routingKeys", []),
            accept=service.get("accept", [])
        )
