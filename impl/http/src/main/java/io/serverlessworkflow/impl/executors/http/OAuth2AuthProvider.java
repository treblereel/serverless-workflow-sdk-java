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
package io.serverlessworkflow.impl.executors.http;

import io.serverlessworkflow.api.types.OAuth2AuthenticationData;
import io.serverlessworkflow.api.types.OAuth2AuthenticationPolicy;
import io.serverlessworkflow.api.types.OAuth2AuthenticationPropertiesEndpoints;
import io.serverlessworkflow.api.types.Oauth2;
import io.serverlessworkflow.api.types.Workflow;
import io.serverlessworkflow.impl.TaskContext;
import io.serverlessworkflow.impl.WorkflowApplication;
import io.serverlessworkflow.impl.WorkflowContext;
import io.serverlessworkflow.impl.WorkflowModel;
import io.serverlessworkflow.impl.executors.http.auth.jwt.JWKSValidator;
import io.serverlessworkflow.impl.executors.http.auth.jwt.JWT;
import io.serverlessworkflow.impl.executors.http.auth.requestbuilder.AuthRequestBuilder;
import io.serverlessworkflow.impl.executors.http.auth.requestbuilder.OAuthRequestBuilder;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.client.Invocation.Builder;
import java.net.URI;
import java.util.List;
import java.util.ServiceLoader;

public class OAuth2AuthProvider implements AuthProvider {

  private final JWKSValidator jwksValidator;

  private final Oauth2 oauth2;
  private AuthRequestBuilder requestBuilder;

  private static final String BEARER_TOKEN = "Bearer %s";

  private static String DEFAULT_JWKS_URL = "oauth2/introspect";

  public OAuth2AuthProvider(
      WorkflowApplication application, Workflow workflow, OAuth2AuthenticationPolicy authPolicy) {
    oauth2 = authPolicy.getOauth2();
    if (oauth2.getOAuth2ConnectAuthenticationProperties() != null) {
      this.requestBuilder = new OAuthRequestBuilder(application, oauth2);
    } else if (oauth2.getOAuth2AuthenticationPolicySecret() != null) {
      throw new UnsupportedOperationException("Secrets are still not supported");
    }

    this.jwksValidator =
        ServiceLoader.load(JWKSValidator.class)
            .findFirst()
            .orElseThrow(() -> new IllegalStateException("No JWKSValidator implementation found"));
  }

  @Override
  public Builder build(
      Builder builder, WorkflowContext workflow, TaskContext task, WorkflowModel model) {
    return builder;
  }

  @Override
  public void preRequest(
      Invocation.Builder builder, WorkflowContext workflow, TaskContext task, WorkflowModel model) {
    JWT jwt = requestBuilder.build(workflow, task, model).get();

    String[] issuers = getIssuers();
    String[] audience = getAudience();

    jwksValidator.validate(jwt, issuers, audience, introspectionURI());

    builder.header(AuthProviderFactory.AUTH_HEADER_NAME, String.format(BEARER_TOKEN, jwt.token()));
  }

  private URI introspectionURI() {
    OAuth2AuthenticationPropertiesEndpoints endpoints =
        oauth2
            .getOAuth2ConnectAuthenticationProperties()
            .getOAuth2ConnectAuthenticationProperties()
            .getEndpoints();

    OAuth2AuthenticationData authenticationData =
        oauth2.getOAuth2ConnectAuthenticationProperties().getOAuth2AuthenticationData();

    String baseUri =
        authenticationData.getAuthority().getLiteralUri().toString().replaceAll("/$", "");
    String introspectionURI = DEFAULT_JWKS_URL;
    if (endpoints != null && endpoints.getIntrospection() != null) {
      introspectionURI = endpoints.getIntrospection().replaceAll("^/", "");
    }
    return URI.create(baseUri + "/" + introspectionURI);
  }

  private String[] getAudience() {
    if (oauth2.getOAuth2ConnectAuthenticationProperties().getOAuth2AuthenticationData() != null
        && oauth2
                .getOAuth2ConnectAuthenticationProperties()
                .getOAuth2AuthenticationData()
                .getAudiences()
            != null) {
      List<String> asList =
          oauth2
              .getOAuth2ConnectAuthenticationProperties()
              .getOAuth2AuthenticationData()
              .getAudiences();
      return asList.toArray(new String[0]);
    }
    return null;
  }

  private String[] getIssuers() {
    if (oauth2.getOAuth2ConnectAuthenticationProperties().getOAuth2AuthenticationData() != null
        && oauth2
                .getOAuth2ConnectAuthenticationProperties()
                .getOAuth2AuthenticationData()
                .getIssuers()
            != null) {
      List<String> asList =
          oauth2
              .getOAuth2ConnectAuthenticationProperties()
              .getOAuth2AuthenticationData()
              .getIssuers();
      return asList.toArray(new String[0]);
    }
    return null;
  }
}
