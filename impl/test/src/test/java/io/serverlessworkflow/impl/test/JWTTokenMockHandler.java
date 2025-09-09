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
package io.serverlessworkflow.impl.test;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JWTTokenMockHandler {

  private final KeyPair keyPair;
  private final String keyId = "test";

  public JWTTokenMockHandler() {
    KeyPairGenerator keyPairGenerator;
    try {
      keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("Failed to generate RSA key pair", e);
    }
    keyPairGenerator.initialize(2048);
    this.keyPair = keyPairGenerator.generateKeyPair();
  }

  public String generateToken(
      String subject, String issuer, String[] audiences, long expirationMinutes) {
    Algorithm algorithm =
        Algorithm.RSA256((RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate());

    Instant now = Instant.now();
    Instant expiration = now.plus(expirationMinutes, ChronoUnit.MINUTES);
    JWTCreator.Builder builder =
        JWT.create().withKeyId(keyId).withSubject(subject).withIssuer(issuer);
    if (audiences != null && audiences.length > 0) {
      builder.withAudience(audiences);
    }

    return builder
        .withIssuedAt(Date.from(now))
        .withExpiresAt(Date.from(expiration))
        .sign(algorithm);
  }

  public Map<String, Object> generateOAuth2TokenResponse(
      String subject, String issuer, long expirationMinutes) {
    return generateOAuth2TokenResponse(subject, issuer, null, expirationMinutes);
  }

  public Map<String, Object> generateOAuth2TokenResponse(
      String subject, String issuer, String[] audiences, long expirationMinutes) {
    String accessToken = generateToken(subject, issuer, audiences, expirationMinutes);
    long expiresInSeconds = expirationMinutes * 60;

    Map<String, Object> response = new HashMap<>();
    response.put("access_token", accessToken);
    response.put("token_type", "Bearer");
    response.put("expires_in", expiresInSeconds);
    response.put("scope", "read write");

    return response;
  }

  public Map<String, Object> generateOpenIDCTokenResponse(
      String subject, String issuer, long expirationMinutes) {
    Map<String, Object> response = generateOAuth2TokenResponse(subject, issuer, expirationMinutes);
    response.put("scope", "openid" + response.get("scope"));
    return response;
  }

  public String generateOAuth2TokenResponseJson(
      String subject, String issuer, long expirationMinutes) {
    return generateOAuth2TokenResponseJson(subject, issuer, null, expirationMinutes);
  }

  public String generateOAuth2TokenResponseJson(
      String subject, String issuer, String[] audiences, long expirationMinutes) {
    Map<String, Object> response =
        generateOAuth2TokenResponse(subject, issuer, audiences, expirationMinutes);
    try {
      ObjectMapper mapper = new ObjectMapper();
      return mapper.writeValueAsString(response);
    } catch (Exception e) {
      throw new RuntimeException("Failed to serialize OAuth2 response", e);
    }
  }

  public String generateOpenIDCTokenResponseJson(
      String subject, String issuer, long expirationMinutes) {
    Map<String, Object> response = generateOpenIDCTokenResponse(subject, issuer, expirationMinutes);
    try {
      ObjectMapper mapper = new ObjectMapper();
      return mapper.writeValueAsString(response);
    } catch (Exception e) {
      throw new RuntimeException("Failed to serialize OAuth2 response", e);
    }
  }

  public Map<String, Object> createJWKS() {
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    String modulus =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(publicKey.getModulus().toByteArray());
    String exponent =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(publicKey.getPublicExponent().toByteArray());

    Map<String, Object> jwk = new HashMap<>();
    jwk.put("kty", "RSA");
    jwk.put("use", "sig");
    jwk.put("kid", keyId);
    jwk.put("alg", "RS256");
    jwk.put("n", modulus);
    jwk.put("e", exponent);

    Map<String, Object> jwks = new HashMap<>();
    jwks.put("keys", new Object[] {jwk});

    return jwks;
  }
}
