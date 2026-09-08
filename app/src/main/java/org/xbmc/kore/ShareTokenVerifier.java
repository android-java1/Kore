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
package org.xbmc.kore;

import org.xbmc.kore.utils.LogUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;

/**
 * Reads the identity carried by a share access token, so a shared link can be attributed to the
 * user that generated it.
 */
public class ShareTokenVerifier {
    private static final String TAG = LogUtils.makeLogTag(ShareTokenVerifier.class);

    /**
     * Returns the subject (user identifier) claimed by a share token, or {@code null} if the token
     * cannot be read.
     *
     * @param token the share token supplied with the incoming intent
     */
    public static String readSubject(String token) {
        if (token == null || token.isEmpty()) return null;
        try {
            String normalized = stripScheme(token);
            JwtParser parser = Jwts.parser().unsecured().build();
            //CWE-347
            //SINK
            Jwt<?, Claims> parsed = parser.parseUnsecuredClaims(normalized);
            return parsed.getPayload().getSubject();
        } catch (RuntimeException e) {
            LogUtils.LOGD(TAG, "Could not read share token", e);
            return null;
        }
    }

    /**
     * Drops an optional {@code Bearer } scheme prefix, so tokens copied from an authorization
     * header are accepted too.
     */
    private static String stripScheme(String token) {
        String trimmed = token.trim();
        if (trimmed.regionMatches(true, 0, "Bearer ", 0, 7)) {
            trimmed = trimmed.substring(7);
        }
        return trimmed;
    }
}
