@file:OptIn(ExperimentalCli::class)

package org.dif.didcomm.demo


import kotlinx.cli.*
import org.dif.exceptions.DIDCommException
import org.dif.peerdid.core.DIDDocVerMaterialFormat


val demo = DIDCommDemo()

class PeerDIDCreatorCommand : Subcommand("create-peer-did", "Creates a new Peer DID and corresponding secrets") {

    val authKeysCount by option(
        ArgType.Int,
        description = "Number of authentication keys",
        fullName = "auth-keys-count"
    ).default(1)
    val agreementKeysCount by option(
        ArgType.Int,
        description = "Number of agreement keys",
        fullName = "agreement-keys-count"
    ).default(1)


    override fun execute() {
        val res = try {
            demo.createPeerDID(
                authKeysCount = authKeysCount, agreementKeysCount = agreementKeysCount
            )
        } catch (e: IllegalArgumentException) {
            e.localizedMessage
        }
        println()
        println(res)
        println()
    }

}

enum class Format {
    JWK,
    BASE58,
    MULTIBASE
}

class ResolvePeerDIDCommand : Subcommand("resolve-peer-did", "Resolve a Peer DID to DID Doc JSON") {

    val did by argument(ArgType.String, description = "Peer DID to be resolved")
    val format by option(
        ArgType.Choice<Format>(),
        shortName = "f",
        description = "Peer DID to be resolved"
    ).default(Format.JWK)

    override fun execute() {
        val res = try {
            DIDCommDemo.resolvePeerDID(
                did,
                format = when (format) {
                    Format.JWK -> DIDDocVerMaterialFormat.JWK
                    Format.BASE58 -> DIDDocVerMaterialFormat.BASE58
                    Format.MULTIBASE -> DIDDocVerMaterialFormat.MULTIBASE
                }
            )
        } catch (e: Exception) {
            e.localizedMessage
        }
        println()
        println(res)
        println()
    }

}

class PackCommand : Subcommand("pack", "Packs the message") {

    val message by argument(ArgType.String, description = "Message to pack")
    val to by option(ArgType.String, description = "Receiver's DID").required()
    val from by option(ArgType.String, description = "Sender's DID. Anonymous encryption is used if not set.")
    val signFrom by option(
        ArgType.String,
        fullName = "sign-from",
        description = "Sender's DID for optional signing. The message is not signed if not set."
    )
    val protectSender by option(
        ArgType.Boolean,
        fullName = "protect-sender",
        description = "Whether the sender's ID (DID) must be hidden. True by default."
    ).default(true)

    override fun execute() {
        val res = try {
            demo.pack(
                data = message, to = to, from = from, signFrom = signFrom, protectSender = protectSender
            ).packedMessage
        } catch (e: DIDCommException) {
            e.localizedMessage
        }
        println()
        println(res)
        println()
    }

}

class UnpackCommand : Subcommand("unpack", "Unpacks the message") {

    val message by argument(ArgType.String, description = "Message to unpack")

    override fun execute() {
        val res = try {
            val unpackRes = demo.unpack(message)
            unpackRes.from?.let {
                "authcrypted ${unpackRes.message} from ${unpackRes.from} to ${unpackRes.to}"
            } ?: {
                "anoncrypted ${unpackRes.message} to ${unpackRes.to}"
            }
        } catch (e: DIDCommException) {
            e.localizedMessage
        }
        println()
        println(res)
        println()
    }

}

fun main(args: Array<String>) {
    val parser = ArgParser("didcomm-cli")
    parser.subcommands(PeerDIDCreatorCommand(), ResolvePeerDIDCommand(), PackCommand(), UnpackCommand())
    parser.parse(args)
}
