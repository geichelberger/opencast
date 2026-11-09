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

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.opencastproject.graphql.schema.builder.TestSchemas.assertData;
import static org.opencastproject.graphql.schema.builder.TestSchemas.fetcher;
import static org.opencastproject.graphql.schema.builder.TestSchemas.schema;

import org.opencastproject.graphql.provider.GraphQLCodeRegistryProvider;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import graphql.GraphQL;
import graphql.schema.DataFetcher;
import graphql.schema.FieldCoordinates;
import graphql.schema.GraphQLCodeRegistry;
import graphql.schema.GraphQLSchema;

class CodeRegistryBuilderTest {

  @Test
  void returnsSchemaUnchangedWithoutChanges() {
    GraphQLSchema schema = schema();

    GraphQLSchema result = new CodeRegistryBuilder().withSchema(schema)
        .withCodeRegistryProviders(List.of(codeRegistry -> null))
        .build();

    assertSame(schema, result);
  }

  @Test
  void appliesProvidersInTurn() {
    GraphQLCodeRegistryProvider first = fetcher("Query", "existing", "first");
    // the second provider sees the registry of the first one and builds on it
    GraphQLCodeRegistryProvider second = codeRegistry -> {
      DataFetcher<?> previous = codeRegistry.getDataFetcher(FieldCoordinates.coordinates("Query", "existing"),
          schema().getQueryType().getFieldDefinition("existing"));
      return GraphQLCodeRegistry.newCodeRegistry(codeRegistry)
          .dataFetcher(FieldCoordinates.coordinates("Query", "existing"),
              (DataFetcher<Object>) env -> previous.get(env) + " and second");
    };

    GraphQLSchema schema = new CodeRegistryBuilder().withSchema(schema())
        .withCodeRegistryProviders(List.of(first, second))
        .build();

    assertData(Map.of("existing", "first and second"), GraphQL.newGraphQL(schema).build().execute("{ existing }"));
  }

}
