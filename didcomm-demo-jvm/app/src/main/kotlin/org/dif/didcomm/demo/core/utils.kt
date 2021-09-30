package org.dif.didcomm.demo.core

import com.google.gson.GsonBuilder
import org.dif.common.VerificationMaterial
import org.dif.common.VerificationMaterialFormat
import org.dif.common.VerificationMethodType
import org.dif.secret.Secret

fun toJson(value: Any?) =
    GsonBuilder().create().toJson(value)

fun jwkToSecret(jwk: Map<String, Any>): Secret =
    Secret(
        kid = jwk["kid"].toString(),
        type = VerificationMethodType.JSON_WEB_KEY_2020,
        verificationMaterial = VerificationMaterial(
            format = VerificationMaterialFormat.JWK,
            value = toJson(jwk)
        )
    )

//fun secretToJwk(secret: Secret) =
//