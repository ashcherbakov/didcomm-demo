package org.dif.didcomm.demo

import org.dif.DIDComm
import org.dif.didcomm.demo.core.PeerDIDCreator
import org.dif.didcomm.demo.diddoc.DIDDocResolverPeerDID
import org.dif.didcomm.demo.secrets.SecretResolverDemo
import org.dif.didcomm.demo.secrets.SecretResolverEditable
import org.dif.message.Message
import org.dif.model.PackEncryptedParams
import org.dif.model.PackEncryptedResult
import org.dif.model.UnpackParams
import org.dif.peerdid.core.DIDDocVerMaterialFormat
import org.dif.utils.divideDIDFragment
import java.util.*

class DIDCommDemo(secretsResolver: SecretResolverEditable? = null) {

    data class UnpackResult(val message: String, val from: String?, val to: String, val res: org.dif.model.UnpackResult)

    companion object {
        fun resolvePeerDID(did: String, format: DIDDocVerMaterialFormat) = org.dif.peerdid.resolvePeerDID(did, format)
    }


    val secretsResolver = secretsResolver ?: SecretResolverDemo()

    fun createPeerDID(
        authKeysCount: Int = 1,
        agreementKeysCount: Int = 1,
        serviceEndpoint: String? = null,
        serviceRoutingKeys: List<String> = emptyList()
    ) = PeerDIDCreator(secretsResolver).createPeerDID(
        authKeysCount,
        agreementKeysCount,
        serviceEndpoint,
        serviceRoutingKeys
    )

    fun pack(
        data: String,
        to: String,
        from: String? = null,
        signFrom: String? = null,
        protectSender: Boolean = true
    ): PackEncryptedResult {
        val didComm = DIDComm(DIDDocResolverPeerDID(), secretsResolver)
        val message = Message.builder(
            id = UUID.randomUUID().toString(),
            body = mapOf("msg" to data),
            type = "my-protocol/1.0"
        ).build()
        var builder = PackEncryptedParams
            .builder(message, to)
            .forward(false)
            .protectSenderId(protectSender)
        builder = from?.let { builder.from(it) } ?: builder
        builder = signFrom?.let { builder.signFrom(it) } ?: builder
        val params = builder.build()
        return didComm.packEncrypted(params)
    }

    fun unpack(packedMsg: String): UnpackResult {
        val didComm = DIDComm(DIDDocResolverPeerDID(), secretsResolver)
        val res = didComm.unpack(UnpackParams.Builder(packedMsg).build())
        val msg = res.message.body["msg"].toString()
        val to = res.metadata.encryptedTo?.let { divideDIDFragment(it.first()).first() } ?: ""
        val from = res.metadata.encryptedFrom?.let { divideDIDFragment(it).first() }
        return UnpackResult(
            message = msg,
            from = from, to = to, res = res
        )
    }
}