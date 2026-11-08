package com.offlinepass.app.crypto

/**
 * The OpenPGP operations the vault save path needs, as an interface so
 * tests can stub OpenKeyChain (device-only IPC) and exercise VaultSession's
 * save transaction on the JVM. The production implementation is
 * [OpenPgpClient].
 */
interface OpenPgpOps {

    suspend fun lookupKeyIds(
        userIds: Array<String>,
        requestData: android.content.Intent? = null
    ): OpenPgpClient.KeyLookup

    suspend fun encryptTo(keyIds: LongArray, source: java.io.File, target: java.io.File): Boolean

    suspend fun fetchPublicKeyArmored(keyId: Long): OpenPgpClient.PublicKey

    suspend fun trySignDetached(
        data: ByteArray,
        keyId: Long?,
        requestData: android.content.Intent? = null
    ): OpenPgpClient.SignDetached

    /** Convenience over [trySignDetached]: the armored signature, or null. */
    suspend fun signDetached(data: ByteArray, keyId: Long): String? =
        (trySignDetached(data, keyId) as? OpenPgpClient.SignDetached.Ok)?.armored

    /** Asks OpenKeyChain which key to sign with (its own picker; may need
     *  an interaction round-trip via [requestData]). Used when the vault
     *  has no stored signer yet — recipient lookups return ENCRYPTION
     *  subkeys, which cannot sign. */
    suspend fun pickSignKey(requestData: android.content.Intent? = null): OpenPgpClient.SignKey
}
