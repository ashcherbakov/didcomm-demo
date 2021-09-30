package org.dif.didcomm.demo

import org.dif.didcomm.demo.core.PeerDIDCreator
import org.dif.didcomm.demo.secrets.SecretResolverDemo
import org.dif.didcomm.demo.secrets.SecretResolverEditable

class DIDCommDemo(secretsResolver: SecretResolverEditable? = null) {

    private val secretsResolver = secretsResolver ?: SecretResolverDemo()

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

    fun pack() {
        //val didComm = DIDComm()
    }
}