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

import org.opencastproject.graphql.provider.GraphQLMutationProvider;
import org.opencastproject.graphql.provider.GraphQLQueryProvider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import graphql.schema.GraphQLFieldDefinition;
import graphql.schema.GraphQLObjectType;
import graphql.schema.GraphQLSchema;

/**
 * Adds the fields of query and mutation providers to the Query and Mutation types of a built schema. Their data
 * fetchers have to be registered by a {@link org.opencastproject.graphql.provider.GraphQLCodeRegistryProvider}.
 *
 * <p>A field that already exists is not replaced: it is skipped and logged, so a provider cannot silently override a
 * built-in field and its access checks.
 */
public class QueryMutationBuilder {

  private static final Logger logger = LoggerFactory.getLogger(QueryMutationBuilder.class);

  private GraphQLSchema schema;

  private List<GraphQLQueryProvider> queryProviders = Collections.emptyList();

  private List<GraphQLMutationProvider> mutationProviders = Collections.emptyList();

  /**
   * @return the schema with the added fields, or the given schema if no provider contributes a field
   */
  public GraphQLSchema build() {
    Objects.requireNonNull(schema, "schema cannot be null");
    final List<GraphQLFieldDefinition> queries = queryProviders.stream()
        .filter(Objects::nonNull)
        .map(GraphQLQueryProvider::getQueries)
        .filter(Objects::nonNull)
        .flatMap(Collection::stream)
        .collect(Collectors.toList());
    final List<GraphQLFieldDefinition> mutations = mutationProviders.stream()
        .filter(Objects::nonNull)
        .map(GraphQLMutationProvider::getMutations)
        .filter(Objects::nonNull)
        .flatMap(Collection::stream)
        .collect(Collectors.toList());
    if (queries.isEmpty() && mutations.isEmpty()) {
      return schema;
    }

    final GraphQLObjectType queryType = addFields(schema.getQueryType(), queries);
    final GraphQLObjectType mutationType = mutations.isEmpty()
        ? schema.getMutationType()
        : addFields(Objects.requireNonNull(schema.getMutationType(), "Schema has no mutation type"), mutations);
    return schema.transform(schemaBuilder -> schemaBuilder.query(queryType).mutation(mutationType));
  }

  private static GraphQLObjectType addFields(GraphQLObjectType type, List<GraphQLFieldDefinition> fields) {
    if (fields.isEmpty()) {
      return type;
    }
    return type.transform(typeBuilder -> {
      final Set<String> names = new HashSet<>();
      type.getFieldDefinitions().forEach(field -> names.add(field.getName()));
      for (GraphQLFieldDefinition field : fields) {
        if (names.add(field.getName())) {
          typeBuilder.field(field);
        } else {
          logger.warn("Ignoring field '{}' from a provider: type {} already has a field with this name",
              field.getName(), type.getName());
        }
      }
    });
  }

  public QueryMutationBuilder withSchema(GraphQLSchema schema) {
    this.schema = schema;
    return this;
  }

  public QueryMutationBuilder withQueryProviders(List<GraphQLQueryProvider> queryProviders) {
    this.queryProviders = queryProviders != null ? queryProviders : Collections.emptyList();
    return this;
  }

  public QueryMutationBuilder withMutationProviders(List<GraphQLMutationProvider> mutationProviders) {
    this.mutationProviders = mutationProviders != null ? mutationProviders : Collections.emptyList();
    return this;
  }

}
