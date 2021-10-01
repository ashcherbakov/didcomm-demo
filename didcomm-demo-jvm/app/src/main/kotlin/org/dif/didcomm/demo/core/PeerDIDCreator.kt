package org.dif.didcomm.demo.core

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import io.ipfs.multibase.Base58
import org.dif.didcomm.demo.secrets.SecretResolverEditable
import org.dif.peerdid.core.*
import org.dif.peerdid.createPeerDIDNumalgo0
import org.dif.peerdid.createPeerDIDNumalgo2
import org.dif.peerdid.resolvePeerDID

class PeerDIDCreator(private val secretsResolver: SecretResolverEditable) {


    private val authPrivateKeysJwk = mutableListOf<MutableMap<String, Any>>()
    private var authPublicKeysPeerDid = mutableListOf<PublicKeyAuthentication>()
    private var agreemPrivateKeysJwk = mutableListOf<MutableMap<String, Any>>()
    private var agreemPublicKeysPeerDid = mutableListOf<PublicKeyAgreement>()
    private var service: String = ""
    private var did: String = ""

    fun createPeerDID(
        authKeysCount: Int = 1,
        agreementKeysCount: Int = 1,
        serviceEndpoint: String? = null,
        serviceRoutingKeys: List<String> = emptyList()
    ): String {
        generateKeys(authKeysCount, agreementKeysCount)
        generateService(serviceEndpoint, serviceRoutingKeys)
        createPeerDID()
        saveKeys()
        return did
    }

    private fun generateKeys(authKeysCount: Int, agreementKeysCount: Int) {
        for (i in 1..authKeysCount) {
            val authKeys = generateEd25519Key()
            authPublicKeysPeerDid.add(jwkEd25519ToPeerDidKey(authKeys))
            authPrivateKeysJwk.add(authKeys.toJSONObject())
        }
        for (i in 1..agreementKeysCount) {
            val agreemKeys = generateX25519Key()
            agreemPublicKeysPeerDid.add(jwkX25519ToPeerDidKey(agreemKeys))
            agreemPrivateKeysJwk.add(agreemKeys.toJSONObject())
        }
    }

    private fun generateService(serviceEndpoint: String?, serviceRoutingKeys: List<String>) {
        // TODO
    }

    private fun createPeerDID() {
        if (authPublicKeysPeerDid.size == 1 && agreemPublicKeysPeerDid.isEmpty() and service.isEmpty())
            did = createPeerDIDNumalgo0(authPublicKeysPeerDid[0])
        else
            did = createPeerDIDNumalgo2(
                signingKeys = authPublicKeysPeerDid,
                encryptionKeys = agreemPublicKeysPeerDid,
                service = service
            )
    }

    private fun saveKeys() {
        // update private key kids
        assignKidToPrivateKey(authPrivateKeysJwk, did, "authentication")
        assignKidToPrivateKey(agreemPrivateKeysJwk, did, "keyAgreement")

        // save private keys in the secrets resolver
        authPrivateKeysJwk.forEach {
            secretsResolver.addSecret(jwkToSecret(it))
        }
        agreemPrivateKeysJwk.forEach {
            secretsResolver.addSecret(jwkToSecret(it))
        }

    }

}

private fun generateEd25519Key(): OctetKeyPair =
    OctetKeyPairGenerator(Curve.Ed25519).generate()

private fun generateX25519Key(): OctetKeyPair =
    OctetKeyPairGenerator(Curve.X25519).generate()

private fun jwkEd25519ToPeerDidKey(jwk: OctetKeyPair): PublicKeyAuthentication =
    PublicKeyAuthentication(
        encodingType = EncodingType.BASE58,
        encodedValue = Base58.encode(jwk.decodedX),
        type = PublicKeyTypeAuthentication.ED25519
    )

private fun jwkX25519ToPeerDidKey(jwk: OctetKeyPair): PublicKeyAgreement =
    PublicKeyAgreement(
        encodingType = EncodingType.BASE58,
        encodedValue = Base58.encode(jwk.decodedX),
        type = PublicKeyTypeAgreement.X25519
    )

private fun assignKidToPrivateKey(privateKeys: List<MutableMap<String, Any>>, did: String, field: String) {
    if (privateKeys.isEmpty())
        return
    val didDocJson = resolvePeerDID(did, format = DIDDocVerMaterialFormat.JWK)
    val didDoc = fromJsonToMap(didDocJson)

    val publicKeys = getDidDocField(didDoc, field)
    if (publicKeys.size != privateKeys.size)
        throw IllegalStateException()
    privateKeys.zip(publicKeys).forEach {
        it.first.put("kid", it.second["id"]!!)
    }

}