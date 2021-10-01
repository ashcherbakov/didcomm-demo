package org.dif.didcomm.demo.diddoc

import org.dif.common.VerificationMaterial
import org.dif.common.VerificationMaterialFormat
import org.dif.common.VerificationMethodType
import org.dif.didcomm.demo.core.*
import org.dif.diddoc.DIDCommService
import org.dif.diddoc.DIDDoc
import org.dif.diddoc.DIDDocResolver
import org.dif.diddoc.VerificationMethod
import org.dif.peerdid.core.DIDDocVerMaterialFormat
import org.dif.peerdid.resolvePeerDID
import java.util.*


// TODO: write DID DOC JSON serializers/deserializers

class DIDDocResolverPeerDID : DIDDocResolver {

    override fun resolve(did: String): Optional<DIDDoc> {
        // request DID Doc in JWK format
        val didDocJson = resolvePeerDID(did, format = DIDDocVerMaterialFormat.JWK)
        val didDoc = fromJsonToMap(didDocJson)


        val authentications = getDidDocAuthentications(didDoc)
        val keyAgreements = getDidDocKeyAgreements(didDoc)
        val services = getDidDocServices(didDoc)

        return Optional.ofNullable(
            DIDDoc(
                did = did,
                keyAgreements = keyAgreements.map { it["id"].toString() }.toList(),
                authentications = authentications.map { it["id"].toString() }.toList(),
                verificationMethods = (authentications + keyAgreements).map { getVerificationMethod(it) },
                didCommServices = services.map { getService(it) }.filterNotNull()
            )
        )
    }

}

// assume JWK requested
private fun getVerificationMethod(method: Map<String, Any>) =
    VerificationMethod(
        id = method["id"].toString(),
        type = VerificationMethodType.JSON_WEB_KEY_2020,
        controller = method["controller"].toString(),
        verificationMaterial = VerificationMaterial(
            format = VerificationMaterialFormat.JWK,
            value = toJson(method["publicKeyJwk"])
        )
    )

private fun getService(service: Map<String, Any>): DIDCommService? {
    val serviceType = service["type"]
    if (serviceType != "DIDCommMessaging")
        return null
    return DIDCommService(
        id = service["id"].toString(),
        serviceEndpoint = service["serviceEndpoint"].toString(),
        routingKeys = service.getOrDefault("routingKeys", emptyList<String>()) as List<String>,
        accept = service.getOrDefault("accept", emptyList<String>()) as List<String>
    )
}