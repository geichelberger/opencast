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

import org.opencastproject.graphql.provider.GraphQLCodeRegistryProvider;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

import graphql.schema.GraphQLCodeRegistry;
import graphql.schema.GraphQLSchema;

/**
 * Lets code registry providers extend the code registry of a built schema, in order. Each provider gets the registry
 * built so far, including the data fetchers and access checks of the annotated fields.
 */
public class CodeRegistryBuilder {

  private GraphQLSchema schema;

  private List<GraphQLCodeRegistryProvider> codeRegistryProviders = Collections.emptyList();

  /**
   * @return the schema with the extended code registry, or the given schema if no provider changes it
   */
  public GraphQLSchema build() {
    Objects.requireNonNull(schema, "schema cannot be null");
    GraphQLCodeRegistry codeRegistry = schema.getCodeRegistry();
    boolean changed = false;
    for (GraphQLCodeRegistryProvider provider : codeRegistryProviders) {
      if (provider == null) {
        continue;
      }
      final GraphQLCodeRegistry.Builder builder = provider.getCodeRegistry(codeRegistry);
      if (builder != null) {
        codeRegistry = builder.build();
        changed = true;
      }
    }
    if (!changed) {
      return schema;
    }
    final GraphQLCodeRegistry result = codeRegistry;
    return schema.transform(schemaBuilder -> schemaBuilder.codeRegistry(result));
  }

  public CodeRegistryBuilder withSchema(GraphQLSchema schema) {
    this.schema = schema;
    return this;
  }

  public CodeRegistryBuilder withCodeRegistryProviders(List<GraphQLCodeRegistryProvider> codeRegistryProviders) {
    this.codeRegistryProviders = codeRegistryProviders != null ? codeRegistryProviders : Collections.emptyList();
    return this;
  }

}
