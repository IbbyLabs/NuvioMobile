package com.nuvio.app.features.plugins

import platform.Foundation.NSData

/**
 * AES-GCM implemented in Swift with CryptoKit.
 * Both methods return null on failure, including a failed tag check.
 */
interface NuvioAesGcmProvider {
    /** Returns ciphertext followed by the 16-byte tag. IV must be at least 12 bytes. */
    fun encrypt(key: NSData, iv: NSData, plaintext: NSData): NSData?

    /** Takes ciphertext followed by the 16-byte tag. */
    fun decrypt(key: NSData, iv: NSData, ciphertextAndTag: NSData): NSData?
}

/** Swift registers the provider during app startup. */
object NuvioAesGcm {
    private var provider: NuvioAesGcmProvider? = null

    fun register(provider: NuvioAesGcmProvider) {
        this.provider = provider
    }

    internal fun requireProvider(): NuvioAesGcmProvider =
        provider ?: error("AES-GCM provider is not registered")
}
