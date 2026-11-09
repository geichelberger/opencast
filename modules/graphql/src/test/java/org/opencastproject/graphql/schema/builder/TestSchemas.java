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
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.opencastproject.graphql.provider.GraphQLCodeRegistryProvider;

import java.util.Map;

import graphql.ExecutionResult;
import graphql.Scalars;
import graphql.schema.DataFetcher;
import graphql.schema.FieldCoordinates;
import graphql.schema.GraphQLCodeRegistry;
import graphql.schema.GraphQLFieldDefinition;
import graphql.schema.GraphQLObjectType;
import graphql.schema.GraphQLSchema;

/**
 * A small schema and helpers for the schema builder tests.
 */
final class TestSchemas {

  private TestSchemas() {
  }

  /**
   * @return a schema with a Query field {@code existing} (resolving to "original") and a Mutation field
   *     {@code existingMutation}
   */
  static GraphQLSchema schema() {
    GraphQLObjectType query = GraphQLObjectType.newObject().name("Query").field(field("existing")).build();
    GraphQLObjectType mutation = GraphQLObjectType.newObject().name("Mutation").field(field("existingMutation"))
        .build();
    GraphQLCodeRegistry codeRegistry = GraphQLCodeRegistry.newCodeRegistry()
        .dataFetcher(FieldCoordinates.coordinates("Query", "existing"), (DataFetcher<Object>) env -> "original")
        .build();
    return GraphQLSchema.newSchema().query(query).mutation(mutation).codeRegistry(codeRegistry).build();
  }

  static GraphQLFieldDefinition field(String name) {
    return GraphQLFieldDefinition.newFieldDefinition().name(name).type(Scalars.GraphQLString).build();
  }

  static GraphQLCodeRegistryProvider fetcher(String type, String field, String value) {
    return codeRegistry -> GraphQLCodeRegistry.newCodeRegistry(codeRegistry)
        .dataFetcher(FieldCoordinates.coordinates(type, field), (DataFetcher<Object>) env -> value);
  }

  static void assertData(Map<String, Object> expected, ExecutionResult result) {
    assertTrue(result.getErrors().isEmpty(), result.getErrors().toString());
    assertEquals(expected, result.getData());
  }

}
