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

package org.opencastproject.graphql.schema;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.opencastproject.graphql.provider.GraphQLCodeRegistryProvider;
import org.opencastproject.graphql.provider.GraphQLExtensionProvider;
import org.opencastproject.graphql.provider.GraphQLFieldVisibilityProvider;
import org.opencastproject.graphql.provider.GraphQLQueryProvider;
import org.opencastproject.graphql.type.input.Mutation;
import org.opencastproject.graphql.type.output.Query;
import org.opencastproject.security.api.JaxbOrganization;

import org.junit.jupiter.api.Test;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import graphql.ExecutionResult;
import graphql.GraphQL;
import graphql.Scalars;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLTypeExtension;
import graphql.schema.DataFetcher;
import graphql.schema.DataFetchingEnvironment;
import graphql.schema.FieldCoordinates;
import graphql.schema.GraphQLCodeRegistry;
import graphql.schema.GraphQLFieldDefinition;
import graphql.schema.GraphQLSchema;
import graphql.schema.visibility.BlockedFields;

/**
 * Builds a real schema from an annotated extension plus programmatic providers.
 */
class SchemaBuilderTest {

  @Test
  void appliesProgrammaticProvidersToTheAnnotatedSchema() {
    GraphQLQueryProvider queries = () -> Set.of(field("extra"), field("hidden"));
    GraphQLCodeRegistryProvider fetchers = codeRegistry -> GraphQLCodeRegistry.newCodeRegistry(codeRegistry)
        .dataFetcher(FieldCoordinates.coordinates("Query", "extra"), (DataFetcher<Object>) env -> "extra value")
        .dataFetcher(FieldCoordinates.coordinates("Query", "hidden"), (DataFetcher<Object>) env -> "secret");
    // visibility is applied after the code registry providers, so it still holds
    GraphQLFieldVisibilityProvider visibility = () -> BlockedFields.newBlock().addPattern("Query.hidden").build();

    GraphQLSchema schema = new SchemaBuilder(new JaxbOrganization("mh_default_org"))
        .extensionProviders(List.of(new TestExtensionProvider()))
        .dynamicTypeProviders(List.of())
        .additionalTypeProviders(List.of())
        .typeFunctionProviders(List.of())
        .queryProviders(List.of(queries))
        .mutationProviders(List.of())
        .codeRegistryProviders(List.of(fetchers))
        .fieldVisibilityProviders(List.of(visibility))
        .build();
    GraphQL graphQL = GraphQL.newGraphQL(schema).build();

    ExecutionResult result = graphQL.execute("{ hello extra }");
    assertTrue(result.getErrors().isEmpty(), result.getErrors().toString());
    assertEquals(Map.of("hello", "world", "extra", "extra value"), result.getData());

    ExecutionResult hidden = graphQL.execute("{ hidden }");
    assertFalse(hidden.getErrors().isEmpty());
    assertEquals("ValidationError", hidden.getErrors().get(0).getErrorType().toString());
  }

  private static GraphQLFieldDefinition field(String name) {
    return GraphQLFieldDefinition.newFieldDefinition().name(name).type(Scalars.GraphQLString).build();
  }

  private static class TestExtensionProvider implements GraphQLExtensionProvider {
    @Override
    public Collection<Class<?>> getExtensions() {
      return List.of(TestQueryExtension.class, TestMutationExtension.class);
    }
  }

  /** An annotated extension, like the built-in ones. */
  @GraphQLTypeExtension(Query.class)
  public static final class TestQueryExtension {

    private TestQueryExtension() {
    }

    @GraphQLField
    public static String hello(final DataFetchingEnvironment environment) {
      return "world";
    }
  }

  /** The annotated schema needs at least one mutation. */
  @GraphQLTypeExtension(Mutation.class)
  public static final class TestMutationExtension {

    private TestMutationExtension() {
    }

    @GraphQLField
    public static String doNothing(final DataFetchingEnvironment environment) {
      return null;
    }
  }

}
