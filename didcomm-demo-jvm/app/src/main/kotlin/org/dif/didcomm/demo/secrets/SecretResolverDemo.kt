package org.dif.didcomm.demo.secrets

import com.google.gson.GsonBuilder
import com.google.gson.reflect.TypeToken
import org.dif.didcomm.demo.core.jwkToSecret
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
            val secretList: List<Map<String, Any>> =
                GsonBuilder().create().fromJson(secretsJson, object : TypeToken<List<Map<String, Any>>>() {}.type)
            secrets = secretList.map { jwkToSecret(it) }.associate { it.kid to it }.toMutableMap()
        }
    }

    private fun save() {
        val secretJson = toJson(secrets.values)
        File(filePath).writeText(secretJson)
    }

    override fun addSecret(secret: Secret) {
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