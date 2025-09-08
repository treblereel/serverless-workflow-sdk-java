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
package io.serverlessworkflow.impl.executors.http.auth.requestbuilder;

import io.serverlessworkflow.impl.TaskContext;
import io.serverlessworkflow.impl.executors.http.auth.jwt.JWT;
import io.serverlessworkflow.impl.executors.http.auth.jwt.JWTConverter;
import java.util.Map;
import java.util.ServiceLoader;

public class AccessTokenProvider {

  private final TokenResponseHandler tokenResponseHandler = new TokenResponseHandler();

  private final TaskContext context;
  private final InvocationHolder invocation;

  private final JWTConverter jwtConverter;

  AccessTokenProvider(InvocationHolder invocation, TaskContext context) {
    this.invocation = invocation;
    this.context = context;

    this.jwtConverter =
        ServiceLoader.load(JWTConverter.class)
            .findFirst()
            .orElseThrow(() -> new IllegalStateException("No JWTConverter implementation found"));
  }

  public JWT get() {
    Map<String, Object> token = tokenResponseHandler.apply(invocation, context);
    return jwtConverter.fromToken((String) token.get("access_token"));
  }
}
