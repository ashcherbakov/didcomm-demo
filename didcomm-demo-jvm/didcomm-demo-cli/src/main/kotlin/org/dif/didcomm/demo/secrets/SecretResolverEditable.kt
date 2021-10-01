package org.dif.didcomm.demo.secrets

import org.dif.secret.Secret
import org.dif.secret.SecretResolver

interface SecretResolverEditable : SecretResolver {

    fun addSecret(secret: Secret)
    fun getKids(): List<String>
}