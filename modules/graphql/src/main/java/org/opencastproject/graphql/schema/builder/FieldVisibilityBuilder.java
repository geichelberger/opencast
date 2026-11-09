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

import org.opencastproject.graphql.provider.GraphQLFieldVisibilityProvider;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import graphql.schema.GraphQLCodeRegistry;
import graphql.schema.GraphQLSchema;
import graphql.schema.visibility.DefaultGraphqlFieldVisibility;
import graphql.schema.visibility.GraphqlFieldVisibility;

/**
 * Restricts the visible fields of a built schema to those every field visibility provider shows, in addition to the
 * visibility already set in its code registry. Run it last, so no
 * later step can replace the code registry and drop the visibility.
 */
public class FieldVisibilityBuilder {

  private GraphQLSchema schema;

  private List<GraphQLFieldVisibilityProvider> fieldVisibilityProviders = Collections.emptyList();

  /**
   * @return the schema with the field visibility, or the given schema if no provider returns one
   */
  public GraphQLSchema build() {
    Objects.requireNonNull(schema, "schema cannot be null");
    final List<GraphqlFieldVisibility> visibilities = fieldVisibilityProviders.stream()
        .filter(Objects::nonNull)
        .map(GraphQLFieldVisibilityProvider::getFieldVisibility)
        .filter(Objects::nonNull)
        .collect(Collectors.toCollection(ArrayList::new));
    if (visibilities.isEmpty()) {
      return schema;
    }
    // Keep the visibility a code registry provider may have set
    final GraphqlFieldVisibility existing = schema.getCodeRegistry().getFieldVisibility();
    if (existing != null && existing != DefaultGraphqlFieldVisibility.DEFAULT_FIELD_VISIBILITY) {
      visibilities.add(0, existing);
    }
    final GraphqlFieldVisibility visibility = visibilities.size() == 1
        ? visibilities.get(0)
        : new CombinedFieldVisibility(visibilities);
    final GraphQLCodeRegistry codeRegistry = schema.getCodeRegistry()
        .transform(registry -> registry.fieldVisibility(visibility));
    return schema.transform(schemaBuilder -> schemaBuilder.codeRegistry(codeRegistry));
  }

  public FieldVisibilityBuilder withSchema(GraphQLSchema schema) {
    this.schema = schema;
    return this;
  }

  public FieldVisibilityBuilder withFieldVisibilityProviders(
      List<GraphQLFieldVisibilityProvider> fieldVisibilityProviders
  ) {
    this.fieldVisibilityProviders = fieldVisibilityProviders != null
        ? fieldVisibilityProviders
        : Collections.emptyList();
    return this;
  }

}
