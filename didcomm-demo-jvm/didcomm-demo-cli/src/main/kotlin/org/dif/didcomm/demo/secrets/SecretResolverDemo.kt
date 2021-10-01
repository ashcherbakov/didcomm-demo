package org.dif.didcomm.demo.secrets

import org.dif.didcomm.demo.core.fromJsonToList
import org.dif.didcomm.demo.core.jwkToSecret
import org.dif.didcomm.demo.core.secretToJwk
import org.dif.didcomm.demo.core.toJson
import org.dif.secret.Secret
import java.io.File
import java.util.*
import kotlin.io.path.Path
import kotlin.io.path.exists


class SecretResolverDemo(private val filePath: String = "secrets.json") : SecretResolverEditable {

    private val secrets: MutableMap<String, Secret>

    init {
        if (!Path(filePath).exists()) {
            secrets = mutableMapOf()
            save()
        } else {
            val secretsJson = File(filePath).readText()
            secrets = if (secretsJson.isNotEmpty()) {
                fromJsonToList(secretsJson).map { jwkToSecret(it) }.associate { it.kid to it }.toMutableMap()
            } else {
                mutableMapOf()
            }
        }
    }

    private fun save() {
        val secretJson = toJson(secrets.values.map { secretToJwk(it) })
        File(filePath).writeText(secretJson)
    }

    override fun addSecret(secret: Secret) {
        // did:peer:2.Ez6LSjsNTqNGe7RZoNATSeY8tCkvvbkzkGmrR54Rb2tBRCess.Ez6LSecetHn9KLDWnu81qW7YJ3zEr23wa8vccNubz4LCU7HqZ.Vz6MkrhZfwgyQ6NsWp5YnnbrDGFnNg5YbNagWvPVtTwkCvs95.Vz6Mkod5yFYVtUCzmZg2JAorQ5apFwjwt5qRZG93xpcihPVdh#6MkrhZfwgyQ6NsWp5YnnbrDGFnNg5YbNagWvPVtTwkCvs95
        secrets.put(secret.kid, secret)
        save()
    }

    override fun getKids(): List<String> =
        secrets.keys.toList()

    override fun findKey(kid: String): Optional<Secret> =
        Optional.ofNullable(secrets.get(kid))

    override fun findKeys(kids: List<String>): Set<String> =
        kids.intersect(secrets.keys)


}