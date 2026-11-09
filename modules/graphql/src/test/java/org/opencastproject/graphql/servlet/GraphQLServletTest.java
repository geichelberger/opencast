/*
 * Licensed to The Apereo Foundation under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 *
 * The Apereo Foundation licenses this file to you under the Educational
 * Community License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License
 * at:
 *
 *   http://opensource.org/licenses/ecl2.txt
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package org.opencastproject.graphql.servlet;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.opencastproject.graphql.config.GraphQLConfiguration;
import org.opencastproject.graphql.execution.ExecutionService;

import org.easymock.EasyMock;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.Set;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

class GraphQLServletTest {

  private final ExecutionService executionService = EasyMock.createMock(ExecutionService.class);
  private final GraphQLConfiguration configuration = EasyMock.createMock(GraphQLConfiguration.class);
  private final GraphQLServlet servlet = new GraphQLServlet(executionService, configuration);

  @Test
  void answersMalformedPostBodyWithGraphQLErrorBody() throws Exception {
    HttpServletRequest request = EasyMock.createMock(HttpServletRequest.class);
    HttpServletResponse response = EasyMock.createMock(HttpServletResponse.class);
    StringWriter body = new StringWriter();
    expectNoCors(request, response);

    final var bytes = new ByteArrayInputStream("{not json".getBytes(StandardCharsets.UTF_8));
    EasyMock.expect(request.getInputStream()).andReturn(new ServletInputStream() {
      @Override
      public int read() {
        return bytes.read();
      }

      @Override
      public boolean isFinished() {
        return bytes.available() == 0;
      }

      @Override
      public boolean isReady() {
        return true;
      }

      @Override
      public void setReadListener(javax.servlet.ReadListener readListener) {
      }
    });
    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
    response.setCharacterEncoding("UTF-8");
    response.setContentType("application/graphql-response+json");
    EasyMock.expect(response.getWriter()).andReturn(new PrintWriter(body));
    EasyMock.replay(request, response, executionService, configuration);

    servlet.doPost(request, response);

    EasyMock.verify(request, response, executionService, configuration);
    String json = body.toString();
    assertTrue(json.contains("\"errors\""), json);
    assertTrue(json.contains("Invalid JSON request body"), json);
    // Parser internals must not leak to the client
    assertFalse(json.contains("line:"), json);
  }

  @Test
  void answersInvalidVariablesParameterWithGraphQLErrorBody() throws Exception {
    HttpServletRequest request = EasyMock.createMock(HttpServletRequest.class);
    HttpServletResponse response = EasyMock.createMock(HttpServletResponse.class);
    StringWriter body = new StringWriter();
    expectNoCors(request, response);

    EasyMock.expect(request.getParameter("query")).andReturn("{ __typename }");
    EasyMock.expect(request.getParameter("operationName")).andReturn(null);
    EasyMock.expect(request.getParameter("variables")).andReturn("{oops");
    EasyMock.expect(request.getParameter("extensions")).andReturn(null);
    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
    response.setCharacterEncoding("UTF-8");
    response.setContentType("application/graphql-response+json");
    EasyMock.expect(response.getWriter()).andReturn(new PrintWriter(body));
    EasyMock.replay(request, response, executionService, configuration);

    servlet.doGet(request, response);

    EasyMock.verify(request, response, executionService, configuration);
    String json = body.toString();
    assertTrue(json.contains("\"errors\""), json);
    assertTrue(json.contains("Invalid JSON in parameter 'variables'"), json);
  }

  private void expectNoCors(HttpServletRequest request, HttpServletResponse response) {
    EasyMock.expect(request.getHeader("Origin")).andReturn(null);
    response.addHeader("Vary", "Origin");
  }

  @Test
  void preflightFromConfiguredOriginIsAllowed() throws Exception {
    HttpServletRequest request = EasyMock.createMock(HttpServletRequest.class);
    HttpServletResponse response = EasyMock.createMock(HttpServletResponse.class);
    EasyMock.expect(request.getHeader("Origin")).andReturn("https://app.example.org");
    EasyMock.expect(configuration.corsAllowedOrigins()).andReturn(Set.of("https://app.example.org"));
    response.addHeader("Vary", "Origin");
    response.setHeader("Access-Control-Allow-Origin", "https://app.example.org");
    response.setHeader("Access-Control-Allow-Credentials", "true");
    response.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    response.setHeader("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, Origin");
    response.flushBuffer();
    EasyMock.replay(request, response, executionService, configuration);

    servlet.doOptions(request, response);

    EasyMock.verify(request, response, executionService, configuration);
  }

  @Test
  void preflightFromUnknownOriginGetsNoCorsHeaders() throws Exception {
    HttpServletRequest request = EasyMock.createMock(HttpServletRequest.class);
    HttpServletResponse response = EasyMock.createMock(HttpServletResponse.class);
    EasyMock.expect(request.getHeader("Origin")).andReturn("https://evil.example.org");
    EasyMock.expect(configuration.corsAllowedOrigins()).andReturn(Set.of("https://app.example.org"));
    response.addHeader("Vary", "Origin");
    response.flushBuffer();
    EasyMock.replay(request, response, executionService, configuration);

    servlet.doOptions(request, response);

    // no Access-Control-* header may be set, which the strict mock verifies
    EasyMock.verify(request, response, executionService, configuration);
  }

  @Test
  void actualResponseCarriesAllowOriginForConfiguredOrigin() throws Exception {
    HttpServletRequest request = EasyMock.createMock(HttpServletRequest.class);
    HttpServletResponse response = EasyMock.createMock(HttpServletResponse.class);
    StringWriter body = new StringWriter();
    EasyMock.expect(request.getHeader("Origin")).andReturn("https://app.example.org");
    EasyMock.expect(configuration.corsAllowedOrigins()).andReturn(Set.of("*"));
    response.addHeader("Vary", "Origin");
    response.setHeader("Access-Control-Allow-Origin", "*");
    EasyMock.expect(request.getParameter("query")).andReturn(null);
    EasyMock.expect(request.getParameter("operationName")).andReturn(null);
    EasyMock.expect(request.getParameter("variables")).andReturn(null);
    EasyMock.expect(request.getParameter("extensions")).andReturn(null);
    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
    response.setCharacterEncoding("UTF-8");
    response.setContentType("application/graphql-response+json");
    EasyMock.expect(response.getWriter()).andReturn(new PrintWriter(body));
    EasyMock.replay(request, response, executionService, configuration);

    servlet.doGet(request, response);

    // the CORS header is also present on error responses
    EasyMock.verify(request, response, executionService, configuration);
  }

}
