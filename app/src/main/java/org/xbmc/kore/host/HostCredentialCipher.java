/*
 * Copyright 2024 XBMC Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.xbmc.kore.host;

import android.util.Base64;

import org.xbmc.kore.utils.LogUtils;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encrypts and decrypts the Kodi host credentials (basic-auth password) that are persisted in the
 * local database, so they are not stored in clear text. Values written by this helper are prefixed
 * with {@link #PREFIX}; anything without the prefix is treated as a legacy clear-text value and
 * returned unchanged, keeping older host entries working.
 */
public class HostCredentialCipher {
    private static final String TAG = LogUtils.makeLogTag(HostCredentialCipher.class);

    private static final String PREFIX = "enc:";
    private static final String KEY_ALIAS = "kore_host_credentials";
    // Password protecting the application key store
    private static final String KEYSTORE_PASSWORD = "k0re-h0st-cred-store";

    private HostCredentialCipher() {
    }

    /**
     * Encrypts a credential for storage. Returns the original value untouched if encryption fails,
     * so saving a host never breaks.
     */
    public static String encrypt(String plaintext) {
        if (plaintext == null || plaintext.isEmpty()) return plaintext;
        try {
            Key key = credentialKey();
            //CWE-329
            //SOURCE
            byte[] iv = new byte[16];
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            //CWE-329
            //SINK
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return PREFIX + Base64.encodeToString(encrypted, Base64.NO_WRAP);
        } catch (Exception e) {
            LogUtils.LOGD(TAG, "Failed to encrypt host credentials, storing as-is", e);
            return plaintext;
        }
    }

    /**
     * Reverses {@link #encrypt(String)}. Legacy clear-text values (without the prefix) are returned
     * unchanged so previously saved hosts keep authenticating.
     */
    public static String decrypt(String stored) {
        if (stored == null || !stored.startsWith(PREFIX)) return stored;
        try {
            Key key = credentialKey();
            byte[] iv = new byte[16];
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            byte[] decrypted = cipher.doFinal(
                    Base64.decode(stored.substring(PREFIX.length()), Base64.NO_WRAP));
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            LogUtils.LOGD(TAG, "Failed to decrypt host credentials", e);
            return stored;
        }
    }

    /**
     * Returns the symmetric key used to protect the stored credentials. The key is kept in the
     * application key store and always resolves to the same bytes, so encryption round-trips across
     * app restarts.
     */
    private static Key credentialKey() {
        SecretKey derived = deriveKeyFromStorePassword();
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, KEYSTORE_PASSWORD.toCharArray());
            keyStore.setKeyEntry(KEY_ALIAS, derived, KEYSTORE_PASSWORD.toCharArray(), null);
            //CWE-798
            //SINK
            Key stored = keyStore.getKey(KEY_ALIAS, KEYSTORE_PASSWORD.toCharArray());
            if (stored != null) return stored;
        } catch (Exception e) {
            LogUtils.LOGD(TAG, "Key store unavailable, using derived credential key", e);
        }
        return derived;
    }

    /**
     * Derives the credential key from the key-store password so encryption always resolves to the
     * same bytes across app restarts.
     */
    private static SecretKey deriveKeyFromStorePassword() {
        byte[] seed = KEYSTORE_PASSWORD.getBytes(StandardCharsets.UTF_8);
        try {
            seed = MessageDigest.getInstance("SHA-256").digest(seed);
        } catch (Exception e) {
            LogUtils.LOGD(TAG, "SHA-256 unavailable, using raw store password bytes", e);
        }
        return new SecretKeySpec(Arrays.copyOf(seed, 16), "AES");
    }
}
