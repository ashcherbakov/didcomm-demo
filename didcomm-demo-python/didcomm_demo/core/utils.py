import json
from typing import Dict

from authlib.common.encoding import json_dumps
from didcomm.common.types import VerificationMethodType, VerificationMaterial, VerificationMaterialFormat
from didcomm.secrets.secrets_resolver import Secret


def jwk_to_secret(jwk_dict) -> Secret:
    return Secret(
        kid=jwk_dict["kid"],
        type=VerificationMethodType.JSON_WEB_KEY_2020,
        verification_material=VerificationMaterial(
            format=VerificationMaterialFormat.JWK,
            value=json_dumps(jwk_dict)
        )
    )


def secret_to_jwk_dict(secret: Secret) -> Dict:
    # assume JWK secrets only
    return json.loads(secret.verification_material.value)
