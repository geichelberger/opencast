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

import org.opencastproject.graphql.config.GraphQLConfiguration;
import org.opencastproject.graphql.execution.ExecutionErrorResult;
import org.opencastproject.graphql.execution.ExecutionService;
import org.opencastproject.graphql.util.GraphQLObjectMapper;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ServiceScope;
import org.osgi.service.http.whiteboard.propertytypes.HttpWhiteboardContextSelect;
import org.osgi.service.http.whiteboard.propertytypes.HttpWhiteboardServletName;
import org.osgi.service.http.whiteboard.propertytypes.HttpWhiteboardServletPattern;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

import graphql.ExecutionResult;
import graphql.GraphqlErrorBuilder;
import graphql.language.Document;
import graphql.language.OperationDefinition;
import graphql.parser.InvalidSyntaxException;
import graphql.parser.Parser;

@Component(
    service = { HttpServlet.class, Servlet.class },
    scope = ServiceScope.PROTOTYPE
)
@HttpWhiteboardServletName(GraphQLServlet.GRAPHQL_ENDPOINT)
@HttpWhiteboardServletPattern(GraphQLServlet.GRAPHQL_ENDPOINT + "/*")
@HttpWhiteboardContextSelect("(osgi.http.whiteboard.context.name=opencast)")
public class GraphQLServlet extends HttpServlet implements Servlet {

  // QUERY is a constant that represents the "query" string
  private static final String QUERY = "query";

  // OPERATION_NAME is a constant that represents the "operationName" string
  private static final String OPERATION_NAME = "operationName";

  // VARIABLES is a constant that represents the "variables" string
  private static final String VARIABLES = "variables";

  // EXTENSIONS is a constant that represents the "extensions" string
  private static final String EXTENSIONS = "extensions";

  // APPLICATION_GRAPHQL is a constant that represents the "application/graphql" string
  private static final String APPLICATION_GRAPHQL = "application/graphql-response+json";

  private static final String JSON_MEDIA_TYPE = "application/json";

  // GRAPHQL_ENDPOINT is a constant that represents the "/graphql" string
  static final String GRAPHQL_ENDPOINT = "/graphql";

  private final ExecutionService executionService;

  private final GraphQLConfiguration configuration;

  private final ObjectMapper objectMapper;

  @Activate
  public GraphQLServlet(
      @Reference ExecutionService executionService,
      @Reference GraphQLConfiguration configuration
  ) {
    this.executionService = executionService;
    this.configuration = configuration;
    this.objectMapper = GraphQLObjectMapper.newInstance();
  }

  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    corsHeaders(req, resp);
    try {
      String query = req.getParameter(QUERY);
      String operationName = req.getParameter(OPERATION_NAME);
      String variablesParameter = req.getParameter(VARIABLES);
      String extensionsParameter = req.getParameter(EXTENSIONS);

      Map<String, Object> variables = deserializeMap(VARIABLES, variablesParameter);
      Map<String, Object> extensions = deserializeMap(EXTENSIONS, extensionsParameter);

      if (containsNonQueryOperation(query)) {
        throw new WebApplicationException("Mutations are only allowed with POST", Response.Status.METHOD_NOT_ALLOWED);
      }

      execute(query, operationName, variables, extensions, resp);
    } catch (WebApplicationException e) {
      sendError(resp, e);
    }
  }

  private void execute(
      String query,
      String operationName,
      Map<String, Object> variables,
      Map<String, Object> extensions,
      HttpServletResponse resp
  ) throws IOException {
    validateQuery(query);
    ExecutionResult result = executionService.execute(query, operationName, variables, extensions);
    resp.setCharacterEncoding(StandardCharsets.UTF_8.name());
    resp.setContentType(APPLICATION_GRAPHQL);
    try (PrintWriter out = resp.getWriter()) {
      objectMapper.writeValue(out, result.toSpecification());
    }
  }

  /**
   * Answer a rejected request with a GraphQL error body instead of the container's HTML error page.
   */
  private void sendError(HttpServletResponse resp, WebApplicationException e) throws IOException {
    ExecutionResult result = ExecutionErrorResult.newExecutionResult()
        .addError(GraphqlErrorBuilder.newError().message(e.getMessage()).build())
        .build();
    resp.setStatus(e.getResponse().getStatus());
    resp.setCharacterEncoding(StandardCharsets.UTF_8.name());
    resp.setContentType(APPLICATION_GRAPHQL);
    try (PrintWriter out = resp.getWriter()) {
      objectMapper.writeValue(out, result.toSpecification());
    }
  }

  private Map<String, Object> deserializeMap(String name, String parameter) {
    Map<String, Object> variables = new HashMap<>();
    if ((parameter != null) && (!parameter.isBlank())) {
      TypeReference<Map<String, Object>> typeRef = new TypeReference<>() { };
      try {
        variables = objectMapper.readValue(parameter, typeRef);
      } catch (JsonProcessingException e) {
        throw new WebApplicationException("Invalid JSON in parameter '" + name + "'", e, Response.Status.BAD_REQUEST);
      }
    }
    return variables;
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    corsHeaders(req, resp);
    try {
      // Only accept JSON. Other content types such as text/plain can be sent cross-site by a plain HTML form without
      // a CORS preflight, which would allow cross-site request forgery.
      if (!isJson(req.getContentType())) {
        throw new WebApplicationException("Content-Type must be application/json",
            Response.Status.UNSUPPORTED_MEDIA_TYPE);
      }
      TypeReference<HashMap<String,Object>> typeRef = new TypeReference<>() { };
      Map<String, Object> body;
      try {
        body = objectMapper.readValue(req.getInputStream(), typeRef);
      } catch (JsonProcessingException e) {
        throw new WebApplicationException("Invalid JSON request body", e, Response.Status.BAD_REQUEST);
      }
      if (body == null) {
        throw new WebApplicationException("Missing request body", Response.Status.BAD_REQUEST);
      }

      String query = getAsString(QUERY, body);
      String operationName = getAsString(OPERATION_NAME, body);
      Map<String, Object> variables = getAsMap(VARIABLES, body);
      Map<String, Object> extensions = getAsMap(EXTENSIONS, body);

      execute(query, operationName, variables, extensions, resp);
    } catch (WebApplicationException e) {
      sendError(resp, e);
    }
  }

  private static String getAsString(String key, Map<String, Object> map) {
    var value = map.get(key);
    if (value != null && !(value instanceof String)) {
      throw new WebApplicationException("Invalid value for '" + key + "'",
          Response.Status.BAD_REQUEST);
    }
    return (String) value;
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> getAsMap(String key, Map<String, Object> map) {
    var value = map.get(key);
    if (value != null && !(value instanceof Map)) {
      throw new WebApplicationException("Invalid value for '" + key + "'",
          Response.Status.BAD_REQUEST);
    }
    return (Map<String, Object>) value;
  }

  private static boolean isJson(String contentType) {
    if (contentType == null) {
      return false;
    }
    String mediaType = contentType.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
    return JSON_MEDIA_TYPE.equals(mediaType);
  }

  /**
   * @return {@code true} if the document contains a mutation or subscription. Unparsable queries return
   *     {@code false} and are rejected with a syntax error during execution.
   */
  private static boolean containsNonQueryOperation(String query) {
    if (query == null || query.isBlank()) {
      return false;
    }
    // Operation types are case sensitive keywords. Skip parsing the query a second time for the usual case of a
    // query without them.
    if (!query.contains("mutation") && !query.contains("subscription")) {
      return false;
    }
    final Document document;
    try {
      document = Parser.parse(query);
    } catch (InvalidSyntaxException e) {
      return false;
    }
    return document.getDefinitionsOfType(OperationDefinition.class).stream()
        .anyMatch(operation -> operation.getOperation() != OperationDefinition.Operation.QUERY);
  }

  private void validateQuery(String query) {
    if (query == null || query.isBlank()) {
      throw new WebApplicationException("Invalid value for '" + QUERY + "'", Response.Status.BAD_REQUEST);
    }
  }

  @Override
  protected void doOptions(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    if (corsHeaders(req, resp)) {
      resp.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      resp.setHeader("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, Origin");
    }
    resp.flushBuffer();
  }

  /**
   * Allow cross-origin browser access for configured origins only. The header is added to every response, including
   * errors, because browsers check it on the actual request as well as on the preflight.
   *
   * @return {@code true} if the request origin is allowed
   */
  private boolean corsHeaders(HttpServletRequest req, HttpServletResponse resp) {
    resp.addHeader("Vary", "Origin");
    final String origin = req.getHeader("Origin");
    if (origin == null) {
      return false;
    }
    final Set<String> allowedOrigins = configuration.corsAllowedOrigins();
    if (allowedOrigins.contains("*")) {
      resp.setHeader("Access-Control-Allow-Origin", "*");
      return true;
    }
    if (allowedOrigins.contains(origin)) {
      resp.setHeader("Access-Control-Allow-Origin", origin);
      // Only for explicitly configured origins. Browsers refuse credentials together with a wildcard origin.
      resp.setHeader("Access-Control-Allow-Credentials", "true");
      return true;
    }
    return false;
  }

}
