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

package org.opencastproject.graphql.schema.builder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.opencastproject.graphql.provider.GraphQLFieldVisibilityProvider;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import graphql.ExecutionResult;
import graphql.GraphQL;
import graphql.Scalars;
import graphql.schema.DataFetcher;
import graphql.schema.FieldCoordinates;
import graphql.schema.GraphQLCodeRegistry;
import graphql.schema.GraphQLFieldDefinition;
import graphql.schema.GraphQLObjectType;
import graphql.schema.GraphQLSchema;
import graphql.schema.visibility.BlockedFields;

class FieldVisibilityBuilderTest {

  @Test
  void returnsSchemaUnchangedWithoutVisibility() {
    GraphQLSchema schema = schema();

    assertSame(schema, apply(schema, List.of()));
    assertSame(schema, apply(schema, List.of(() -> null)));
  }

  @Test
  void hidesFieldsBlockedByAnyProvider() {
    GraphQLSchema schema = apply(schema(), List.of(block("Query.b"), block("Query.c")));
    GraphQL graphQL = GraphQL.newGraphQL(schema).build();

    ExecutionResult visible = graphQL.execute("{ a }");
    assertTrue(visible.getErrors().isEmpty(), visible.getErrors().toString());
    assertEquals(Map.of("a", "a"), visible.getData());

    for (String hidden : List.of("b", "c")) {
      ExecutionResult result = graphQL.execute("{ " + hidden + " }");
      assertFalse(result.getErrors().isEmpty(), hidden);
      assertEquals("ValidationError", result.getErrors().get(0).getErrorType().toString(), hidden);
    }
  }

  @Test
  void keepsVisibilityOfTheCodeRegistry() {
    GraphQLSchema base = schema();
    GraphQLCodeRegistry registry = base.getCodeRegistry()
        .transform(builder -> builder.fieldVisibility(BlockedFields.newBlock().addPattern("Query.a").build()));
    GraphQLSchema schema = base.transform(builder -> builder.codeRegistry(registry));

    GraphQL graphQL = GraphQL.newGraphQL(apply(schema, List.of(block("Query.b")))).build();

    for (String hidden : List.of("a", "b")) {
      ExecutionResult result = graphQL.execute("{ " + hidden + " }");
      assertFalse(result.getErrors().isEmpty(), hidden);
    }
    assertTrue(graphQL.execute("{ c }").getErrors().isEmpty());
  }

  @Test
  void hidesBlockedFieldsFromIntrospection() {
    GraphQLSchema schema = apply(schema(), List.of(block("Query.b"), block("Query.c")));

    ExecutionResult result = GraphQL.newGraphQL(schema).build()
        .execute("{ __type(name: \"Query\") { fields { name } } }");

    Map<String, Map<String, List<Map<String, String>>>> data = result.getData();
    List<String> fields = data.get("__type").get("fields").stream()
        .map(field -> field.get("name"))
        .collect(Collectors.toList());
    assertEquals(List.of("a"), fields);
  }

  private static GraphQLSchema apply(GraphQLSchema schema, List<GraphQLFieldVisibilityProvider> providers) {
    return new FieldVisibilityBuilder().withSchema(schema).withFieldVisibilityProviders(providers).build();
  }

  private static GraphQLFieldVisibilityProvider block(String pattern) {
    return () -> BlockedFields.newBlock().addPattern(pattern).build();
  }

  private static GraphQLSchema schema() {
    GraphQLObjectType.Builder query = GraphQLObjectType.newObject().name("Query");
    GraphQLCodeRegistry.Builder codeRegistry = GraphQLCodeRegistry.newCodeRegistry();
    for (String name : List.of("a", "b", "c")) {
      query.field(GraphQLFieldDefinition.newFieldDefinition().name(name).type(Scalars.GraphQLString));
      codeRegistry.dataFetcher(FieldCoordinates.coordinates("Query", name), (DataFetcher<Object>) env -> name);
    }
    return GraphQLSchema.newSchema().query(query.build()).codeRegistry(codeRegistry.build()).build();
  }

}
