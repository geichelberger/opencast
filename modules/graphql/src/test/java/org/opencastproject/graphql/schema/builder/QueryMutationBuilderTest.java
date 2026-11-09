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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.opencastproject.graphql.schema.builder.TestSchemas.assertData;
import static org.opencastproject.graphql.schema.builder.TestSchemas.field;
import static org.opencastproject.graphql.schema.builder.TestSchemas.schema;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import graphql.GraphQL;
import graphql.Scalars;
import graphql.schema.GraphQLFieldDefinition;
import graphql.schema.GraphQLObjectType;
import graphql.schema.GraphQLSchema;

class QueryMutationBuilderTest {

  @Test
  void returnsSchemaUnchangedWithoutFields() {
    GraphQLSchema schema = schema();

    GraphQLSchema result = new QueryMutationBuilder().withSchema(schema)
        .withQueryProviders(List.of(Set::of))
        .withMutationProviders(List.of(() -> null))
        .build();

    assertSame(schema, result);
  }

  @Test
  void addsQueryAndMutationFields() {
    GraphQLSchema schema = new QueryMutationBuilder().withSchema(schema())
        .withQueryProviders(List.of(() -> Set.of(field("extra"))))
        .withMutationProviders(List.of(() -> Set.of(field("doSomething"))))
        .build();

    assertEquals(List.of("existing", "extra"), fieldNames(schema.getQueryType()));
    assertEquals(List.of("existingMutation", "doSomething"), fieldNames(schema.getMutationType()));
    // the original data fetcher is kept
    assertData(Map.of("existing", "original"), GraphQL.newGraphQL(schema).build().execute("{ existing }"));
  }

  @Test
  void doesNotReplaceExistingFields() {
    GraphQLFieldDefinition original = schema().getQueryType().getFieldDefinition("existing");
    GraphQLFieldDefinition replacement = GraphQLFieldDefinition.newFieldDefinition().name("existing")
        .type(Scalars.GraphQLInt).build();

    GraphQLSchema schema = new QueryMutationBuilder().withSchema(schema())
        .withQueryProviders(List.of(() -> Set.of(replacement)))
        .build();

    assertSame(original.getType(), schema.getQueryType().getFieldDefinition("existing").getType());
  }

  private static List<String> fieldNames(GraphQLObjectType type) {
    return type.getFieldDefinitions().stream().map(GraphQLFieldDefinition::getName).collect(Collectors.toList());
  }

}
