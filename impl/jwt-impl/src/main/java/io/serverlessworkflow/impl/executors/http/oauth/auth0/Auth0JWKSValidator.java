/*
 * Copyright 2020-Present The Serverless Workflow Specification Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.serverlessworkflow.impl.executors.http.oauth.auth0;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Verification;
import io.serverlessworkflow.impl.executors.http.auth.jwt.JWKSValidator;
import io.serverlessworkflow.impl.executors.http.auth.jwt.JWT;
import java.net.MalformedURLException;
import java.net.URI;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

public class Auth0JWKSValidator implements JWKSValidator {

  private static final Map<URI, JwkProvider> providers = new HashMap<>();

  private static final int CONNECT_TIMEOUT_MS = 10000;
  private static final int READ_TIMEOUT_MS = 10000;

  @Override
  public void validate(JWT jwt, String[] expectedIssuer, String[] expectedAudience, URI jwksUrl) {
    if (!providers.containsKey(jwksUrl)) {
      try {
        // TODO we might want to allow configuring cache and rate limit settings
        providers.put(
            jwksUrl,
            new JwkProviderBuilder(jwksUrl.toURL())
                .cached(1024, 24, TimeUnit.HOURS)
                .rateLimited(600, 1, TimeUnit.MINUTES)
                .timeouts(CONNECT_TIMEOUT_MS, READ_TIMEOUT_MS)
                .build());
      } catch (MalformedURLException e) {
        throw new IllegalArgumentException("Invalid JWKS URL: " + jwksUrl, e);
      }
    }

    try {
      JwkProvider provider = providers.get(jwksUrl);

      Jwk decoded = provider.get(jwt.keyId());
      PublicKey publicKey = decoded.getPublicKey();
      Algorithm algorithm = createAlgorithm(jwt.algorithm(), publicKey);

      Verification verification = com.auth0.jwt.JWT.require(algorithm);
      if (expectedIssuer != null && expectedIssuer.length > 0) {
        verification.withIssuer(expectedIssuer);
      }
      if (expectedAudience != null && expectedAudience.length > 0) {
        verification.withAudience(expectedAudience);
      }
      JWTVerifier verifier = verification.acceptLeeway(60).build();
      verifier.verify(jwt.token());

    } catch (JwkException e) {
      throw new RuntimeException("Failed to get public key from JWKS: " + e.getMessage(), e);
    } catch (JWTVerificationException e) {
      throw new IllegalArgumentException("Invalid JWT: " + e.getMessage(), e);
    }
  }

  private Algorithm createAlgorithm(String algorithm, PublicKey publicKey) {
    Objects.requireNonNull(algorithm, "Algorithm cannot be null");
    Objects.requireNonNull(publicKey, "PublicKey cannot be null");

    if (algorithm.startsWith("HS")) {
      throw new IllegalArgumentException(
          "HMAC algorithms are not supported with public keys. Use RSA (RS*) or ECDSA (ES*) instead.");
    }

    if (publicKey instanceof RSAPublicKey rsaKey) {
      return switch (algorithm) {
        case "RS256" -> Algorithm.RSA256(rsaKey, null);
        case "RS384" -> Algorithm.RSA384(rsaKey, null);
        case "RS512" -> Algorithm.RSA512(rsaKey, null);
        default -> throw new IllegalArgumentException("Unsupported RSA algorithm: " + algorithm);
      };
    } else if (publicKey instanceof ECPublicKey ecKey) {
      return switch (algorithm) {
        case "ES256" -> Algorithm.ECDSA256(ecKey, null);
        case "ES384" -> Algorithm.ECDSA384(ecKey, null);
        case "ES512" -> Algorithm.ECDSA512(ecKey, null);
        default -> throw new IllegalArgumentException("Unsupported ECDSA algorithm: " + algorithm);
      };
    }

    throw new IllegalArgumentException(
        "Unsupported key type for algorithm "
            + algorithm
            + ": "
            + publicKey.getClass().getSimpleName()
            + ". Supported: RSAPublicKey, ECPublicKey");
  }

  public void clearCache() {
    providers.clear();
  }
}
