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

package org.opencastproject.graphql.execution;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.opencastproject.graphql.exception.GraphQLRuntimeException;
import org.opencastproject.graphql.schema.SchemaService;
import org.opencastproject.security.api.JaxbOrganization;
import org.opencastproject.security.api.JaxbRole;
import org.opencastproject.security.api.JaxbUser;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.security.api.User;

import org.easymock.EasyMock;
import org.junit.jupiter.api.Test;
import org.osgi.framework.BundleContext;

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.util.Map;
import java.util.Set;

import graphql.ExecutionResult;
import graphql.Scalars;
import graphql.schema.DataFetcher;
import graphql.schema.FieldCoordinates;
import graphql.schema.GraphQLCodeRegistry;
import graphql.schema.GraphQLFieldDefinition;
import graphql.schema.GraphQLObjectType;
import graphql.schema.GraphQLSchema;

/**
 * Runs queries through the real graphql-java engine with a small schema.
 */
class ExecutionServiceTest {

  private static final JaxbOrganization ORGANIZATION = new JaxbOrganization("mh_default_org", "Default", null,
      "ROLE_ADMIN", "ROLE_ANONYMOUS", null);

  private static final String INTROSPECTION_QUERY = "{ __schema { queryType { name } } }";

  @Test
  void disablesIntrospectionForAnonymousUsers() {
    ExecutionResult result = execute(user("anonymous", "ROLE_ANONYMOUS"), INTROSPECTION_QUERY);

    assertFalse(result.getErrors().isEmpty());
    assertEquals("IntrospectionDisabled", result.getErrors().get(0).getErrorType().toString());
  }

  @Test
  void allowsIntrospectionForAuthenticatedUsers() {
    ExecutionResult result = execute(user("alice", "ROLE_USER"), INTROSPECTION_QUERY);

    assertTrue(result.getErrors().isEmpty(), result.getErrors().toString());
    Map<String, Object> data = result.getData();
    assertNotNull(data.get("__schema"));
  }

  @Test
  void anonymousUsersCanStillRunRegularQueries() {
    ExecutionResult result = execute(user("anonymous", "ROLE_ANONYMOUS"), "{ hello }");

    assertTrue(result.getErrors().isEmpty(), result.getErrors().toString());
    assertEquals(Map.of("hello", "world"), result.getData());
  }

  @Test
  void hidesDetailsOfUnexpectedExceptions() {
    ExecutionResult result = execute(user("alice", "ROLE_USER"), "{ failsUnexpectedly }");

    assertEquals(1, result.getErrors().size());
    String message = result.getErrors().get(0).getMessage();
    assertEquals(GraphQLRuntimeException.INTERNAL_ERROR_MESSAGE, message);
    assertEquals("InternalError", result.getErrors().get(0).getErrorType().toString());
    assertEquals(java.util.List.of("failsUnexpectedly"), result.getErrors().get(0).getPath());
  }

  @Test
  void hidesDetailsOfWrappedExceptions() {
    ExecutionResult result = execute(user("alice", "ROLE_USER"), "{ failsWrapped }");

    assertEquals(1, result.getErrors().size());
    assertEquals(GraphQLRuntimeException.INTERNAL_ERROR_MESSAGE, result.getErrors().get(0).getMessage());
    assertFalse(result.toSpecification().toString().contains("secret"));
  }

  private static ExecutionResult execute(User user, String query) {
    SchemaService schemaService = EasyMock.createMock(SchemaService.class);
    EasyMock.expect(schemaService.get(ORGANIZATION.getId())).andReturn(schema()).anyTimes();
    SecurityService securityService = EasyMock.createMock(SecurityService.class);
    EasyMock.expect(securityService.getOrganization()).andReturn(ORGANIZATION).anyTimes();
    EasyMock.expect(securityService.getUser()).andReturn(user).anyTimes();
    BundleContext bundleContext = EasyMock.createNiceMock(BundleContext.class);
    EasyMock.replay(schemaService, securityService, bundleContext);

    ExecutionService service = new ExecutionService(schemaService, securityService, bundleContext, config());
    return service.execute(query, null, null, null);
  }

  private static GraphQLSchema schema() {
    GraphQLObjectType queryType = GraphQLObjectType.newObject()
        .name("Query")
        .field(GraphQLFieldDefinition.newFieldDefinition().name("hello").type(Scalars.GraphQLString))
        .field(GraphQLFieldDefinition.newFieldDefinition().name("failsUnexpectedly").type(Scalars.GraphQLString))
        .field(GraphQLFieldDefinition.newFieldDefinition().name("failsWrapped").type(Scalars.GraphQLString))
        .build();
    DataFetcher<Object> unexpected = env -> {
      throw new IllegalStateException("secret: jdbc:mysql://db.internal/opencast");
    };
    DataFetcher<Object> wrapped = env -> {
      throw new GraphQLRuntimeException(new IOException("secret: /srv/opencast/workspace"));
    };
    GraphQLCodeRegistry codeRegistry = GraphQLCodeRegistry.newCodeRegistry()
        .dataFetcher(FieldCoordinates.coordinates("Query", "hello"), (DataFetcher<Object>) env -> "world")
        .dataFetcher(FieldCoordinates.coordinates("Query", "failsUnexpectedly"), unexpected)
        .dataFetcher(FieldCoordinates.coordinates("Query", "failsWrapped"), wrapped)
        .build();
    return GraphQLSchema.newSchema().query(queryType).codeRegistry(codeRegistry).build();
  }

  private static User user(String username, String role) {
    return new JaxbUser(username, null, username, null, "test", ORGANIZATION,
        Set.of(new JaxbRole(role, ORGANIZATION)));
  }

  private static ExecutionService.ExecutionConfiguration config() {
    return new ExecutionService.ExecutionConfiguration() {
      @Override
      public Class<? extends Annotation> annotationType() {
        return ExecutionService.ExecutionConfiguration.class;
      }

      @Override
      public int execution_max_query_complexity() {
        return 1000;
      }

      @Override
      public int execution_max_query_depth() {
        return 25;
      }
    };
  }

}
