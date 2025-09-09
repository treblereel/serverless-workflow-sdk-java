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

import static io.serverlessworkflow.api.WorkflowReader.readWorkflowFromClasspath;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.serverlessworkflow.api.types.Workflow;
import io.serverlessworkflow.impl.WorkflowApplication;
import io.serverlessworkflow.impl.executors.http.auth.jwt.JWKSValidator;
import io.serverlessworkflow.impl.executors.http.oauth.auth0.Auth0JWKSValidator;
import java.io.IOException;
import java.util.Map;
import java.util.ServiceLoader;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class OAuthHTTPWorkflowDefinitionTest {

  private ObjectMapper MAPPER;

  private static final String RESPONSE =
      """
                  {
                      "message": "Hello World"
                  }
                  """;

  private MockWebServer authServer;
  private MockWebServer apiServer;
  private JWTTokenMockHandler jwtTokenHandler;
  private JWKSValidator jwksValidator;

  @BeforeEach
  void setUp() throws IOException {
    authServer = new MockWebServer();
    authServer.start(8888);

    apiServer = new MockWebServer();
    apiServer.start(8081);

    jwksValidator =
        ServiceLoader.load(JWKSValidator.class)
            .findFirst()
            .orElseThrow(() -> new IllegalStateException("No JWKSValidator implementation found"));

    jwtTokenHandler = new JWTTokenMockHandler();
    MAPPER = new ObjectMapper();
  }

  @AfterEach
  void tearDown() throws IOException {
    authServer.shutdown();
    apiServer.shutdown();
    ((Auth0JWKSValidator) jwksValidator).clearCache();
  }

  @Test
  public void testOAuthClientSecretPostPasswordWorkflowExecution() throws Exception {
    String tokenResponse =
        jwtTokenHandler.generateOAuth2TokenResponseJson(
            "serverless-workflow-test", "http://localhost:8888/realms/test-realm", 60);

    String jwksJson = MAPPER.writeValueAsString(jwtTokenHandler.createJWKS());

    authServer.enqueue(
        new MockResponse()
            .setBody(tokenResponse)
            .setHeader("Content-Type", "application/json")
            .setResponseCode(200));

    apiServer.enqueue(
        new MockResponse()
            .setBody(RESPONSE)
            .setHeader("Content-Type", "application/json")
            .setResponseCode(200));

    authServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setHeader("Cache-Control", "public, max-age=3600")
            .setBody(jwksJson));

    Workflow workflow =
        readWorkflowFromClasspath("workflows-samples/oAuthClientSecretPostPasswordHttpCall.yaml");
    Map<String, Object> result;
    try (WorkflowApplication app = WorkflowApplication.builder().build()) {
      result =
          app.workflowDefinition(workflow).instance(Map.of()).start().get().asMap().orElseThrow();
    }
    RecordedRequest tokenRequest = authServer.takeRequest();
    String tokenRequestBody = tokenRequest.getBody().readUtf8();

    assertTrue(result.containsKey("message"));
    assertTrue(result.get("message").toString().contains("Hello World"));

    assertEquals("POST", tokenRequest.getMethod());
    assertEquals("/realms/test-realm/protocol/openid-connect/token", tokenRequest.getPath());
    assertEquals("application/x-www-form-urlencoded", tokenRequest.getHeader("Content-Type"));
    assertTrue(tokenRequestBody.contains("grant_type=password"));
    assertTrue(tokenRequestBody.contains("username=serverless-workflow-test"));
    assertTrue(tokenRequestBody.contains("password=serverless-workflow-test"));
    checkIntrospectRequest("/realms/test-realm/oauth2/introspect", authServer);
    checkApiRequest(tokenResponse, apiServer);
  }

  @Test
  public void testOAuthClientSecretPostWithArgsWorkflowExecution() throws Exception {
    String tokenResponse =
        jwtTokenHandler.generateOAuth2TokenResponseJson(
            "serverless-workflow-test", "http://localhost:8888/realms/test-realm", 60);
    String jwksJson = MAPPER.writeValueAsString(jwtTokenHandler.createJWKS());

    authServer.enqueue(
        new MockResponse()
            .setBody(tokenResponse)
            .setHeader("Content-Type", "application/json")
            .setResponseCode(200));

    apiServer.enqueue(
        new MockResponse()
            .setBody(RESPONSE)
            .setHeader("Content-Type", "application/json")
            .setResponseCode(200));

    authServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setHeader("Cache-Control", "public, max-age=3600")
            .setBody(jwksJson));

    Workflow workflow =
        readWorkflowFromClasspath(
            "workflows-samples/oAuthClientSecretPostPasswordAsArgHttpCall.yaml");
    Map<String, Object> result;
    Map<String, String> params =
        Map.of(
            "clientId", "serverless-workflow",
            "clientSecret", "D0ACXCUKOUrL5YL7j6RQWplMaSjPB8MT",
            "username", "serverless-workflow-test",
            "password", "serverless-workflow-test");

    try (WorkflowApplication app = WorkflowApplication.builder().build()) {
      result =
          app.workflowDefinition(workflow).instance(params).start().get().asMap().orElseThrow();
    }
    RecordedRequest tokenRequest = authServer.takeRequest();
    String tokenRequestBody = tokenRequest.getBody().readUtf8();

    assertTrue(result.containsKey("message"));
    assertTrue(result.get("message").toString().contains("Hello World"));
    assertEquals("POST", tokenRequest.getMethod());
    assertEquals("/realms/test-realm/protocol/openid-connect/token", tokenRequest.getPath());
    assertEquals("application/x-www-form-urlencoded", tokenRequest.getHeader("Content-Type"));
    assertTrue(tokenRequestBody.contains("grant_type=password"));
    assertTrue(tokenRequestBody.contains("username=serverless-workflow-test"));
    assertTrue(tokenRequestBody.contains("password=serverless-workflow-test"));
    checkIntrospectRequest("/realms/test-realm/oauth2/introspect", authServer);
    checkApiRequest(tokenResponse, apiServer);
  }

  @Test
  public void testOAuthClientSecretPostWithArgsNoEndPointWorkflowExecution() throws Exception {
    String tokenResponse =
        jwtTokenHandler.generateOAuth2TokenResponseJson(
            "serverless-workflow-test", "http://localhost:8888/realms/test-realm", 60);

    authServer.enqueue(
        new MockResponse()
            .setBody(tokenResponse)
            .setHeader("Content-Type", "application/json")
            .setResponseCode(200));

    apiServer.enqueue(
        new MockResponse()
            .setBody(RESPONSE)
            .setHeader("Content-Type", "application/json")
            .setResponseCode(200));

    Map<String, Object> jwks = jwtTokenHandler.createJWKS();
    String jwksJson = MAPPER.writeValueAsString(jwks);

    authServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setHeader("Cache-Control", "public, max-age=3600")
            .setBody(jwksJson));

    Workflow workflow =
        readWorkflowFromClasspath(
            "workflows-samples/oAuthClientSecretPostPasswordNoEndpointsHttpCall.yaml");
    Map<String, Object> result;
    Map<String, String> params =
        Map.of(
            "clientId", "serverless-workflow",
            "clientSecret", "D0ACXCUKOUrL5YL7j6RQWplMaSjPB8MT",
            "username", "serverless-workflow-test",
            "password", "serverless-workflow-test");

    try (WorkflowApplication app = WorkflowApplication.builder().build()) {
      result =
          app.workflowDefinition(workflow).instance(params).start().get().asMap().orElseThrow();
    }
    RecordedRequest tokenRequest = authServer.takeRequest();
    String tokenRequestBody = tokenRequest.getBody().readUtf8();

    assertTrue(result.containsKey("message"));
    assertTrue(result.get("message").toString().contains("Hello World"));
    assertEquals("POST", tokenRequest.getMethod());
    assertEquals("/realms/test-realm/oauth2/token", tokenRequest.getPath());
    assertEquals("application/x-www-form-urlencoded", tokenRequest.getHeader("Content-Type"));
    assertTrue(tokenRequestBody.contains("grant_type=password"));
    assertTrue(tokenRequestBody.contains("username=serverless-workflow-test"));
    assertTrue(tokenRequestBody.contains("password=serverless-workflow-test"));
    checkIntrospectRequest("/realms/test-realm/oauth2/introspect", authServer);
    checkApiRequest(tokenResponse, apiServer);
  }

  @Test
  public void testOAuthClientSecretPostWithArgsAllGrantsWorkflowExecution() throws Exception {
    String[] audiences = new String[] {"serverless-workflow", "another-audience", "third-audience"};
    String tokenResponse =
        jwtTokenHandler.generateOAuth2TokenResponseJson(
            "serverless-workflow-test", "http://localhost:8888/realms/test-realm", audiences, 60);
    String jwksJson = MAPPER.writeValueAsString(jwtTokenHandler.createJWKS());

    authServer.enqueue(
        new MockResponse()
            .setBody(tokenResponse)
            .setHeader("Content-Type", "application/json")
            .setResponseCode(200));

    apiServer.enqueue(
        new MockResponse()
            .setBody(RESPONSE)
            .setHeader("Content-Type", "application/json")
            .setResponseCode(200));

    authServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setHeader("Cache-Control", "public, max-age=3600")
            .setBody(jwksJson));

    Workflow workflow =
        readWorkflowFromClasspath(
            "workflows-samples/oAuthClientSecretPostPasswordAllGrantsHttpCall.yaml");
    Map<String, Object> result;
    Map<String, String> params =
        Map.of(
            "clientId", "serverless-workflow",
            "clientSecret", "D0ACXCUKOUrL5YL7j6RQWplMaSjPB8MT",
            "username", "serverless-workflow-test",
            "password", "serverless-workflow-test",
            "openidScope", "openidScope");

    try (WorkflowApplication app = WorkflowApplication.builder().build()) {
      result =
          app.workflowDefinition(workflow).instance(params).start().get().asMap().orElseThrow();
    }
    RecordedRequest tokenRequest = authServer.takeRequest();
    String tokenRequestBody = tokenRequest.getBody().readUtf8();

    assertTrue(result.containsKey("message"));
    assertTrue(result.get("message").toString().contains("Hello World"));
    assertEquals("POST", tokenRequest.getMethod());
    assertEquals("/realms/test-realm/oauth2/token", tokenRequest.getPath());
    assertEquals("application/x-www-form-urlencoded", tokenRequest.getHeader("Content-Type"));
    assertTrue(tokenRequestBody.contains("grant_type=password"));
    assertTrue(tokenRequestBody.contains("username=serverless-workflow-test"));
    assertTrue(tokenRequestBody.contains("password=serverless-workflow-test"));
    assertTrue(
        tokenRequestBody.contains("scope=pets%3Aread+pets%3Awrite+pets%3Adelete+pets%3Acreate"));
    assertTrue(
        tokenRequestBody.contains("audience=serverless-workflow+another-audience+third-audience"));
    checkIntrospectRequest("/realms/test-realm/oauth2/introspect", authServer);
    checkApiRequest(tokenResponse, apiServer);
  }

  @Test
  public void testOAuthClientSecretPostClientCredentialsWorkflowExecution() throws Exception {
    String tokenResponse =
        jwtTokenHandler.generateOAuth2TokenResponseJson(
            "serverless-workflow-test", "http://localhost:8888/realms/test-realm", 60);

    String jwksJson = MAPPER.writeValueAsString(jwtTokenHandler.createJWKS());

    authServer.enqueue(
        new MockResponse()
            .setBody(tokenResponse)
            .setHeader("Content-Type", "application/json")
            .setResponseCode(200));

    authServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setHeader("Cache-Control", "public, max-age=3600")
            .setBody(jwksJson));

    apiServer.enqueue(
        new MockResponse()
            .setBody(RESPONSE)
            .setHeader("Content-Type", "application/json")
            .setResponseCode(200));

    Workflow workflow =
        readWorkflowFromClasspath(
            "workflows-samples/oAuthClientSecretPostClientCredentialsHttpCall.yaml");
    Map<String, Object> result;
    try (WorkflowApplication app = WorkflowApplication.builder().build()) {
      result =
          app.workflowDefinition(workflow).instance(Map.of()).start().get().asMap().orElseThrow();
    }
    RecordedRequest tokenRequest = authServer.takeRequest();
    String tokenRequestBody = tokenRequest.getBody().readUtf8();

    assertTrue(result.containsKey("message"));
    assertTrue(result.get("message").toString().contains("Hello World"));
    assertEquals("POST", tokenRequest.getMethod());
    assertEquals("/realms/test-realm/protocol/openid-connect/token", tokenRequest.getPath());
    assertEquals("application/x-www-form-urlencoded", tokenRequest.getHeader("Content-Type"));
    assertTrue(tokenRequestBody.contains("grant_type=client_credentials"));
    assertTrue(tokenRequestBody.contains("client_id=serverless-workflow"));
    assertTrue(tokenRequestBody.contains("secret=D0ACXCUKOUrL5YL7j6RQWplMaSjPB8MT"));
    checkIntrospectRequest("/realms/test-realm/oauth2/introspect", authServer);
    checkApiRequest(tokenResponse, apiServer);
  }

  @Test
  public void testOAuthClientSecretPostClientCredentialsParamsWorkflowExecution() throws Exception {
    String tokenResponse =
        jwtTokenHandler.generateOAuth2TokenResponseJson(
            "serverless-workflow-test", "http://localhost:8888/realms/test-realm", 60);
    String access_token = MAPPER.readTree(tokenResponse).get("access_token").asText();
    String jwksJson = MAPPER.writeValueAsString(jwtTokenHandler.createJWKS());

    authServer.enqueue(
        new MockResponse()
            .setBody(tokenResponse)
            .setHeader("Content-Type", "application/json")
            .setResponseCode(200));

    apiServer.enqueue(
        new MockResponse()
            .setBody(RESPONSE)
            .setHeader("Content-Type", "application/json")
            .setResponseCode(200));

    authServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setHeader("Cache-Control", "public, max-age=3600")
            .setBody(jwksJson));

    Workflow workflow =
        readWorkflowFromClasspath(
            "workflows-samples/oAuthClientSecretPostClientCredentialsParamsHttpCall.yaml");
    Map<String, Object> result;
    Map<String, String> params =
        Map.of(
            "clientId", "serverless-workflow",
            "clientSecret", "D0ACXCUKOUrL5YL7j6RQWplMaSjPB8MT");

    try (WorkflowApplication app = WorkflowApplication.builder().build()) {
      result =
          app.workflowDefinition(workflow).instance(params).start().get().asMap().orElseThrow();
    }
    RecordedRequest tokenRequest = authServer.takeRequest();
    String tokenRequestBody = tokenRequest.getBody().readUtf8();

    assertTrue(result.containsKey("message"));
    assertTrue(result.get("message").toString().contains("Hello World"));
    assertEquals("POST", tokenRequest.getMethod());
    assertEquals("/realms/test-realm/protocol/openid-connect/token", tokenRequest.getPath());
    assertEquals("application/x-www-form-urlencoded", tokenRequest.getHeader("Content-Type"));
    assertTrue(tokenRequestBody.contains("grant_type=client_credentials"));
    assertTrue(tokenRequestBody.contains("client_id=serverless-workflow"));
    assertTrue(tokenRequestBody.contains("secret=D0ACXCUKOUrL5YL7j6RQWplMaSjPB8MT"));
    checkIntrospectRequest("/realms/test-realm/oauth2/introspect", authServer);
    checkApiRequest(tokenResponse, apiServer);
  }

  @Test
  public void testOAuthClientSecretPostClientCredentialsParamsNoEndpointWorkflowExecution()
      throws Exception {
    String tokenResponse =
        jwtTokenHandler.generateOAuth2TokenResponseJson(
            "serverless-workflow-test", "http://localhost:8888/realms/test-realm", 60);
    String jwksJson = MAPPER.writeValueAsString(jwtTokenHandler.createJWKS());

    authServer.enqueue(
        new MockResponse()
            .setBody(tokenResponse)
            .setHeader("Content-Type", "application/json")
            .setResponseCode(200));

    apiServer.enqueue(
        new MockResponse()
            .setBody(RESPONSE)
            .setHeader("Content-Type", "application/json")
            .setResponseCode(200));

    authServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setHeader("Cache-Control", "public, max-age=3600")
            .setBody(jwksJson));

    Workflow workflow =
        readWorkflowFromClasspath(
            "workflows-samples/oAuthClientSecretPostClientCredentialsParamsNoEndPointHttpCall.yaml");
    Map<String, Object> result;
    Map<String, String> params =
        Map.of(
            "clientId", "serverless-workflow",
            "clientSecret", "D0ACXCUKOUrL5YL7j6RQWplMaSjPB8MT");

    try (WorkflowApplication app = WorkflowApplication.builder().build()) {
      result =
          app.workflowDefinition(workflow).instance(params).start().get().asMap().orElseThrow();
    }
    RecordedRequest tokenRequest = authServer.takeRequest();
    String tokenRequestBody = tokenRequest.getBody().readUtf8();

    assertTrue(result.containsKey("message"));
    assertTrue(result.get("message").toString().contains("Hello World"));
    assertEquals("POST", tokenRequest.getMethod());
    assertEquals("/realms/test-realm/oauth2/token", tokenRequest.getPath());
    assertEquals("application/x-www-form-urlencoded", tokenRequest.getHeader("Content-Type"));
    assertTrue(tokenRequestBody.contains("grant_type=client_credentials"));
    assertTrue(tokenRequestBody.contains("client_id=serverless-workflow"));
    assertTrue(tokenRequestBody.contains("secret=D0ACXCUKOUrL5YL7j6RQWplMaSjPB8MT"));
    checkIntrospectRequest("/realms/test-realm/oauth2/introspect", authServer);
    checkApiRequest(tokenResponse, apiServer);
  }

  @Test
  public void testOAuthJSONPasswordWorkflowExecution() throws Exception {
    String tokenResponse =
        jwtTokenHandler.generateOAuth2TokenResponseJson(
            "serverless-workflow-test", "http://localhost:8888/realms/test-realm", 60);
    String jwksJson = MAPPER.writeValueAsString(jwtTokenHandler.createJWKS());

    authServer.enqueue(
        new MockResponse()
            .setBody(tokenResponse)
            .setHeader("Content-Type", "application/json")
            .setResponseCode(200));

    apiServer.enqueue(
        new MockResponse()
            .setBody(RESPONSE)
            .setHeader("Content-Type", "application/json")
            .setResponseCode(200));

    authServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setHeader("Cache-Control", "public, max-age=3600")
            .setBody(jwksJson));

    Workflow workflow =
        readWorkflowFromClasspath("workflows-samples/oAuthJSONPasswordHttpCall.yaml");
    Map<String, Object> result;
    try (WorkflowApplication app = WorkflowApplication.builder().build()) {
      result =
          app.workflowDefinition(workflow).instance(Map.of()).start().get().asMap().orElseThrow();
    }
    RecordedRequest tokenRequest = authServer.takeRequest();
    String tokenRequestBody = tokenRequest.getBody().readUtf8();
    Map<String, Object> asJson = MAPPER.readValue(tokenRequestBody, Map.class);

    assertTrue(result.containsKey("message"));
    assertTrue(result.get("message").toString().contains("Hello World"));
    assertEquals("POST", tokenRequest.getMethod());
    assertEquals("/realms/test-realm/protocol/openid-connect/token", tokenRequest.getPath());
    assertEquals("application/json", tokenRequest.getHeader("Content-Type"));
    assertTrue(asJson.containsKey("grant_type") && asJson.get("grant_type").equals("password"));
    assertTrue(
        asJson.containsKey("client_id") && asJson.get("client_id").equals("serverless-workflow"));
    assertTrue(
        asJson.containsKey("client_secret")
            && asJson.get("client_secret").equals("D0ACXCUKOUrL5YL7j6RQWplMaSjPB8MT"));
    assertTrue(
        asJson.containsKey("username")
            && asJson.get("username").equals("serverless-workflow-test"));
    assertTrue(
        asJson.containsKey("password")
            && asJson.get("password").equals("serverless-workflow-test"));
    checkIntrospectRequest("/realms/test-realm/oauth2/introspect", authServer);
    checkApiRequest(tokenResponse, apiServer);
  }

  @Test
  public void testOAuthJSONWithArgsWorkflowExecution() throws Exception {
    String tokenResponse =
        jwtTokenHandler.generateOAuth2TokenResponseJson(
            "serverless-workflow-test", "http://localhost:8888/realms/test-realm", 60);
    String jwksJson = MAPPER.writeValueAsString(jwtTokenHandler.createJWKS());

    authServer.enqueue(
        new MockResponse()
            .setBody(tokenResponse)
            .setHeader("Content-Type", "application/json")
            .setResponseCode(200));

    apiServer.enqueue(
        new MockResponse()
            .setBody(RESPONSE)
            .setHeader("Content-Type", "application/json")
            .setResponseCode(200));

    authServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setHeader("Cache-Control", "public, max-age=3600")
            .setBody(jwksJson));

    Workflow workflow =
        readWorkflowFromClasspath("workflows-samples/oAuthJSONPasswordAsArgHttpCall.yaml");
    Map<String, Object> result;
    Map<String, String> params =
        Map.of(
            "clientId", "serverless-workflow",
            "clientSecret", "D0ACXCUKOUrL5YL7j6RQWplMaSjPB8MT",
            "username", "serverless-workflow-test",
            "password", "serverless-workflow-test");

    try (WorkflowApplication app = WorkflowApplication.builder().build()) {
      result =
          app.workflowDefinition(workflow).instance(params).start().get().asMap().orElseThrow();
    }
    RecordedRequest tokenRequest = authServer.takeRequest();
    String tokenRequestBody = tokenRequest.getBody().readUtf8();
    Map<String, Object> asJson = MAPPER.readValue(tokenRequestBody, Map.class);

    assertTrue(result.containsKey("message"));
    assertTrue(result.get("message").toString().contains("Hello World"));
    assertEquals("POST", tokenRequest.getMethod());
    assertEquals("/realms/test-realm/protocol/openid-connect/token", tokenRequest.getPath());
    assertEquals("application/json", tokenRequest.getHeader("Content-Type"));
    assertTrue(asJson.containsKey("grant_type") && asJson.get("grant_type").equals("password"));
    assertTrue(
        asJson.containsKey("client_id") && asJson.get("client_id").equals("serverless-workflow"));
    assertTrue(
        asJson.containsKey("client_secret")
            && asJson.get("client_secret").equals("D0ACXCUKOUrL5YL7j6RQWplMaSjPB8MT"));
    assertTrue(
        asJson.containsKey("username")
            && asJson.get("username").equals("serverless-workflow-test"));
    assertTrue(
        asJson.containsKey("password")
            && asJson.get("password").equals("serverless-workflow-test"));
    checkIntrospectRequest("/realms/test-realm/oauth2/introspect", authServer);
    checkApiRequest(tokenResponse, apiServer);
  }

  @Test
  public void testOAuthJSONWithArgsNoEndPointWorkflowExecution() throws Exception {
    String tokenResponse =
        jwtTokenHandler.generateOAuth2TokenResponseJson(
            "serverless-workflow-test", "http://localhost:8888/realms/test-realm", 60);
    String jwksJson = MAPPER.writeValueAsString(jwtTokenHandler.createJWKS());

    authServer.enqueue(
        new MockResponse()
            .setBody(tokenResponse)
            .setHeader("Content-Type", "application/json")
            .setResponseCode(200));

    authServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setHeader("Cache-Control", "public, max-age=3600")
            .setBody(jwksJson));

    apiServer.enqueue(
        new MockResponse()
            .setBody(RESPONSE)
            .setHeader("Content-Type", "application/json")
            .setResponseCode(200));

    Workflow workflow =
        readWorkflowFromClasspath("workflows-samples/oAuthJSONPasswordNoEndpointsHttpCall.yaml");
    Map<String, Object> result;
    Map<String, String> params =
        Map.of(
            "clientId", "serverless-workflow",
            "clientSecret", "D0ACXCUKOUrL5YL7j6RQWplMaSjPB8MT",
            "username", "serverless-workflow-test",
            "password", "serverless-workflow-test");

    try (WorkflowApplication app = WorkflowApplication.builder().build()) {
      result =
          app.workflowDefinition(workflow).instance(params).start().get().asMap().orElseThrow();
    }
    RecordedRequest tokenRequest = authServer.takeRequest();
    String tokenRequestBody = tokenRequest.getBody().readUtf8();
    Map<String, Object> asJson = MAPPER.readValue(tokenRequestBody, Map.class);

    assertTrue(result.containsKey("message"));
    assertTrue(result.get("message").toString().contains("Hello World"));
    assertEquals("POST", tokenRequest.getMethod());
    assertEquals("/realms/test-realm/oauth2/token", tokenRequest.getPath());
    assertEquals("application/json", tokenRequest.getHeader("Content-Type"));
    assertTrue(asJson.containsKey("grant_type") && asJson.get("grant_type").equals("password"));
    assertTrue(
        asJson.containsKey("client_id") && asJson.get("client_id").equals("serverless-workflow"));
    assertTrue(
        asJson.containsKey("client_secret")
            && asJson.get("client_secret").equals("D0ACXCUKOUrL5YL7j6RQWplMaSjPB8MT"));
    assertTrue(
        asJson.containsKey("username")
            && asJson.get("username").equals("serverless-workflow-test"));
    assertTrue(
        asJson.containsKey("password")
            && asJson.get("password").equals("serverless-workflow-test"));
    checkIntrospectRequest("/realms/test-realm/oauth2/introspect", authServer);
    checkApiRequest(tokenResponse, apiServer);
  }

  @Test
  public void testOAuthJSONWithArgsAllGrantsWorkflowExecution() throws Exception {
    String[] audiences = new String[] {"serverless-workflow", "another-audience", "third-audience"};
    String tokenResponse =
        jwtTokenHandler.generateOAuth2TokenResponseJson(
            "serverless-workflow-test", "http://localhost:8888/realms/test-realm", audiences, 60);
    String jwksJson = MAPPER.writeValueAsString(jwtTokenHandler.createJWKS());

    authServer.enqueue(
        new MockResponse()
            .setBody(tokenResponse)
            .setHeader("Content-Type", "application/json")
            .setResponseCode(200));

    authServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setHeader("Cache-Control", "public, max-age=3600")
            .setBody(jwksJson));

    apiServer.enqueue(
        new MockResponse()
            .setBody(RESPONSE)
            .setHeader("Content-Type", "application/json")
            .setResponseCode(200));

    Workflow workflow =
        readWorkflowFromClasspath("workflows-samples/oAuthJSONPasswordAllGrantsHttpCall.yaml");
    Map<String, Object> result;
    Map<String, String> params =
        Map.of(
            "clientId", "serverless-workflow",
            "clientSecret", "D0ACXCUKOUrL5YL7j6RQWplMaSjPB8MT",
            "username", "serverless-workflow-test",
            "password", "serverless-workflow-test",
            "openidScope", "openidScope",
            "audience", "account");

    try (WorkflowApplication app = WorkflowApplication.builder().build()) {
      result =
          app.workflowDefinition(workflow).instance(params).start().get().asMap().orElseThrow();
    }
    RecordedRequest tokenRequest = authServer.takeRequest();
    String tokenRequestBody = tokenRequest.getBody().readUtf8();
    Map<String, Object> asJson = MAPPER.readValue(tokenRequestBody, Map.class);

    assertTrue(result.containsKey("message"));
    assertTrue(result.get("message").toString().contains("Hello World"));
    assertEquals("POST", tokenRequest.getMethod());
    assertEquals("/realms/test-realm/oauth2/token", tokenRequest.getPath());
    assertEquals("application/json", tokenRequest.getHeader("Content-Type"));
    assertTrue(asJson.containsKey("grant_type") && asJson.get("grant_type").equals("password"));
    assertTrue(
        asJson.containsKey("client_id") && asJson.get("client_id").equals("serverless-workflow"));
    assertTrue(
        asJson.containsKey("client_secret")
            && asJson.get("client_secret").equals("D0ACXCUKOUrL5YL7j6RQWplMaSjPB8MT"));
    assertTrue(
        asJson.containsKey("username")
            && asJson.get("username").equals("serverless-workflow-test"));
    assertTrue(
        asJson.containsKey("password")
            && asJson.get("password").equals("serverless-workflow-test"));
    assertTrue(
        asJson.containsKey("scope")
            && asJson.get("scope").equals("pets:read pets:write pets:delete pets:create"));
    assertTrue(
        asJson.containsKey("audience")
            && asJson
                .get("audience")
                .equals("serverless-workflow another-audience third-audience"));
    checkIntrospectRequest("/realms/test-realm/oauth2/introspect", authServer);
    checkApiRequest(tokenResponse, apiServer);
  }

  @Test
  public void testOAuthJSONClientCredentialsWorkflowExecution() throws Exception {
    String tokenResponse =
        jwtTokenHandler.generateOAuth2TokenResponseJson(
            "serverless-workflow-test", "http://localhost:8888/realms/test-realm", 60);
    String jwksJson = MAPPER.writeValueAsString(jwtTokenHandler.createJWKS());

    authServer.enqueue(
        new MockResponse()
            .setBody(tokenResponse)
            .setHeader("Content-Type", "application/json")
            .setResponseCode(200));

    authServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setHeader("Cache-Control", "public, max-age=3600")
            .setBody(jwksJson));

    apiServer.enqueue(
        new MockResponse()
            .setBody(RESPONSE)
            .setHeader("Content-Type", "application/json")
            .setResponseCode(200));

    Workflow workflow =
        readWorkflowFromClasspath("workflows-samples/oAuthJSONClientCredentialsHttpCall.yaml");
    Map<String, Object> result;
    try (WorkflowApplication app = WorkflowApplication.builder().build()) {
      result =
          app.workflowDefinition(workflow).instance(Map.of()).start().get().asMap().orElseThrow();
    }
    RecordedRequest tokenRequest = authServer.takeRequest();
    String tokenRequestBody = tokenRequest.getBody().readUtf8();
    Map<String, Object> asJson = MAPPER.readValue(tokenRequestBody, Map.class);

    assertTrue(result.containsKey("message"));
    assertTrue(result.get("message").toString().contains("Hello World"));
    assertEquals("POST", tokenRequest.getMethod());
    assertEquals("/realms/test-realm/protocol/openid-connect/token", tokenRequest.getPath());
    assertEquals("application/json", tokenRequest.getHeader("Content-Type"));
    assertTrue(
        asJson.containsKey("grant_type") && asJson.get("grant_type").equals("client_credentials"));
    assertTrue(
        asJson.containsKey("client_id") && asJson.get("client_id").equals("serverless-workflow"));
    assertTrue(
        asJson.containsKey("client_secret")
            && asJson.get("client_secret").equals("D0ACXCUKOUrL5YL7j6RQWplMaSjPB8MT"));
    checkIntrospectRequest("/realms/test-realm/oauth2/introspect", authServer);
    checkApiRequest(tokenResponse, apiServer);
  }

  @Test
  public void testOAuthJSONClientCredentialsParamsWorkflowExecution() throws Exception {
    String tokenResponse =
        jwtTokenHandler.generateOAuth2TokenResponseJson(
            "serverless-workflow-test", "http://localhost:8888/realms/test-realm", 60);
    String jwksJson = MAPPER.writeValueAsString(jwtTokenHandler.createJWKS());

    authServer.enqueue(
        new MockResponse()
            .setBody(tokenResponse)
            .setHeader("Content-Type", "application/json")
            .setResponseCode(200));

    authServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setHeader("Cache-Control", "public, max-age=3600")
            .setBody(jwksJson));

    apiServer.enqueue(
        new MockResponse()
            .setBody(RESPONSE)
            .setHeader("Content-Type", "application/json")
            .setResponseCode(200));

    Workflow workflow =
        readWorkflowFromClasspath(
            "workflows-samples/oAuthJSONClientCredentialsParamsHttpCall.yaml");
    Map<String, Object> result;
    Map<String, String> params =
        Map.of(
            "clientId", "serverless-workflow",
            "clientSecret", "D0ACXCUKOUrL5YL7j6RQWplMaSjPB8MT");

    try (WorkflowApplication app = WorkflowApplication.builder().build()) {
      result =
          app.workflowDefinition(workflow).instance(params).start().get().asMap().orElseThrow();
    }
    RecordedRequest tokenRequest = authServer.takeRequest();
    String tokenRequestBody = tokenRequest.getBody().readUtf8();
    Map<String, Object> asJson = MAPPER.readValue(tokenRequestBody, Map.class);

    assertTrue(result.containsKey("message"));
    assertTrue(result.get("message").toString().contains("Hello World"));
    assertEquals("POST", tokenRequest.getMethod());
    assertEquals("/realms/test-realm/protocol/openid-connect/token", tokenRequest.getPath());
    assertEquals("application/json", tokenRequest.getHeader("Content-Type"));
    assertTrue(
        asJson.containsKey("grant_type") && asJson.get("grant_type").equals("client_credentials"));
    assertTrue(
        asJson.containsKey("client_id") && asJson.get("client_id").equals("serverless-workflow"));
    assertTrue(
        asJson.containsKey("client_secret")
            && asJson.get("client_secret").equals("D0ACXCUKOUrL5YL7j6RQWplMaSjPB8MT"));
    checkIntrospectRequest("/realms/test-realm/oauth2/introspect", authServer);
    checkApiRequest(tokenResponse, apiServer);
  }

  @Test
  public void testOAuthJSONClientCredentialsParamsNoEndpointWorkflowExecution() throws Exception {
    String tokenResponse =
        jwtTokenHandler.generateOAuth2TokenResponseJson(
            "serverless-workflow-test", "http://localhost:8888/realms/test-realm", 60);
    String jwksJson = MAPPER.writeValueAsString(jwtTokenHandler.createJWKS());

    authServer.enqueue(
        new MockResponse()
            .setBody(tokenResponse)
            .setHeader("Content-Type", "application/json")
            .setResponseCode(200));

    apiServer.enqueue(
        new MockResponse()
            .setBody(RESPONSE)
            .setHeader("Content-Type", "application/json")
            .setResponseCode(200));

    authServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setHeader("Cache-Control", "public, max-age=3600")
            .setBody(jwksJson));

    Workflow workflow =
        readWorkflowFromClasspath(
            "workflows-samples/oAuthJSONClientCredentialsParamsNoEndPointHttpCall.yaml");
    Map<String, Object> result;
    Map<String, String> params =
        Map.of(
            "clientId", "serverless-workflow",
            "clientSecret", "D0ACXCUKOUrL5YL7j6RQWplMaSjPB8MT");

    try (WorkflowApplication app = WorkflowApplication.builder().build()) {
      result =
          app.workflowDefinition(workflow).instance(params).start().get().asMap().orElseThrow();
    }
    RecordedRequest tokenRequest = authServer.takeRequest();
    String tokenRequestBody = tokenRequest.getBody().readUtf8();
    Map<String, Object> asJson = MAPPER.readValue(tokenRequestBody, Map.class);

    assertTrue(result.containsKey("message"));
    assertTrue(result.get("message").toString().contains("Hello World"));
    assertEquals("POST", tokenRequest.getMethod());
    assertEquals("/realms/test-realm/oauth2/token", tokenRequest.getPath());
    assertEquals("application/json", tokenRequest.getHeader("Content-Type"));
    assertTrue(
        asJson.containsKey("grant_type") && asJson.get("grant_type").equals("client_credentials"));
    assertTrue(
        asJson.containsKey("client_id") && asJson.get("client_id").equals("serverless-workflow"));
    assertTrue(
        asJson.containsKey("client_secret")
            && asJson.get("client_secret").equals("D0ACXCUKOUrL5YL7j6RQWplMaSjPB8MT"));
    checkIntrospectRequest("/realms/test-realm/oauth2/introspect", authServer);
    checkApiRequest(tokenResponse, apiServer);
  }

  private void checkApiRequest(String tokenResponse, MockWebServer apiServer) throws Exception {
    RecordedRequest petRequest = apiServer.takeRequest();
    assertEquals("GET", petRequest.getMethod());
    assertEquals("/hello", petRequest.getPath());
    String access_token = MAPPER.readTree(tokenResponse).get("access_token").asText();
    assertEquals("Bearer " + access_token, petRequest.getHeader("Authorization"));
  }

  private void checkIntrospectRequest(String expected, MockWebServer apiServer) throws Exception {
    RecordedRequest introspectRequest = authServer.takeRequest();
    assertEquals("GET", introspectRequest.getMethod());
    assertEquals(expected, introspectRequest.getPath());
  }
}
