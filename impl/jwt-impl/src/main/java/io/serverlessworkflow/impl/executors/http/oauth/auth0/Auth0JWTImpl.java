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

import com.auth0.jwt.interfaces.DecodedJWT;
import io.serverlessworkflow.impl.executors.http.auth.jwt.JWT;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public class Auth0JWTImpl implements JWT {

  private final String token;

  private final DecodedJWT jwt;

  Auth0JWTImpl(String token) {
    this.token = Objects.requireNonNull(token, "token");
    jwt = com.auth0.jwt.JWT.decode(token);
  }

  @Override
  public String token() {
    return token;
  }

  @Override
  public <T> Optional<T> claim(String name, Class<T> type) {
    if (name == null || type == null) return Optional.empty();
    try {
      return Optional.of(jwt.getClaim(name).as(type));
    } catch (Exception e) {
      return Optional.empty();
    }
  }

  @Override
  public Optional<String> issuer() {
    return Optional.ofNullable(jwt.getIssuer());
  }

  @Override
  public String keyId() {
    return jwt.getKeyId();
  }

  @Override
  public Optional<String> subject() {
    return Optional.ofNullable(jwt.getSubject());
  }

  @Override
  public List<String> audience() {
    return jwt.getAudience();
  }

  @Override
  public String algorithm() {
    return jwt.getAlgorithm();
  }

  @Override
  public Optional<Instant> issuedAt() {
    return Optional.ofNullable(jwt.getIssuedAt().toInstant());
  }

  @Override
  public Optional<Instant> expiresAt() {
    return Optional.ofNullable(jwt.getExpiresAt().toInstant());
  }

  @Override
  public Optional<String> type() {
    jwt.getKeyId();
    return Optional.ofNullable(jwt.getType());
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof Auth0JWTImpl that)) return false;
    return Objects.equals(token, that.token);
  }

  @Override
  public int hashCode() {
    return Objects.hash(token);
  }
}
