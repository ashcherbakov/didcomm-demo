package org.dif.didcomm.demo.core

import com.google.gson.GsonBuilder
import com.google.gson.reflect.TypeToken
import org.dif.common.VerificationMaterial
import org.dif.common.VerificationMaterialFormat
import org.dif.common.VerificationMethodType
import org.dif.secret.Secret

fun toJson(value: Any?) =
    GsonBuilder().create().toJson(value)

fun fromJsonToList(value: String): List<Map<String, Any>> =
    GsonBuilder().create().fromJson(value, object : TypeToken<List<Map<String, Any>>>() {}.type)

fun fromJsonToMap(value: String): Map<String, Any> =
    GsonBuilder().create().fromJson(value, object : TypeToken<Map<String, Any>>() {}.type)

fun jwkToSecret(jwk: Map<String, Any>): Secret =
    Secret(
        kid = jwk["kid"].toString(),
        type = VerificationMethodType.JSON_WEB_KEY_2020,
        verificationMaterial = VerificationMaterial(
            format = VerificationMaterialFormat.JWK,
            value = toJson(jwk)
        )
    )

fun secretToJwk(secret: Secret): Map<String, Any> =
    fromJsonToMap(secret.verificationMaterial.value)

fun getDidDocField(didDoc: Map<String, Any>, field: String) =
    didDoc.getOrDefault(
        field, emptyList<Map<String, Any>>()
    ) as List<Map<String, Any>>

fun getDidDocAuthentications(didDoc: Map<String, Any>) =
    getDidDocField(didDoc, "authentication")

fun getDidDocKeyAgreements(didDoc: Map<String, Any>) =
    getDidDocField(didDoc, "keyAgreement")

fun getDidDocServices(didDoc: Map<String, Any>) =
    getDidDocField(didDoc, "service")
