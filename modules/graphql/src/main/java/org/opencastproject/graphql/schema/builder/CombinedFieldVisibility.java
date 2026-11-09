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

import java.util.List;
import java.util.stream.Collectors;

import graphql.schema.GraphQLFieldDefinition;
import graphql.schema.GraphQLFieldsContainer;
import graphql.schema.GraphQLInputFieldsContainer;
import graphql.schema.GraphQLInputObjectField;
import graphql.schema.visibility.GraphqlFieldVisibility;

/**
 * Combines several field visibilities: a field is only visible if every one of them shows it.
 */
final class CombinedFieldVisibility implements GraphqlFieldVisibility {

  private final List<GraphqlFieldVisibility> visibilities;

  CombinedFieldVisibility(List<GraphqlFieldVisibility> visibilities) {
    this.visibilities = List.copyOf(visibilities);
  }

  @Override
  public List<GraphQLFieldDefinition> getFieldDefinitions(GraphQLFieldsContainer fieldsContainer) {
    return fieldsContainer.getFieldDefinitions().stream()
        .filter(field -> getFieldDefinition(fieldsContainer, field.getName()) != null)
        .collect(Collectors.toList());
  }

  @Override
  public GraphQLFieldDefinition getFieldDefinition(GraphQLFieldsContainer fieldsContainer, String fieldName) {
    GraphQLFieldDefinition field = fieldsContainer.getFieldDefinition(fieldName);
    for (GraphqlFieldVisibility visibility : visibilities) {
      if (field == null) {
        return null;
      }
      field = visibility.getFieldDefinition(fieldsContainer, fieldName);
    }
    return field;
  }

  @Override
  public List<GraphQLInputObjectField> getFieldDefinitions(GraphQLInputFieldsContainer fieldsContainer) {
    return fieldsContainer.getFieldDefinitions().stream()
        .filter(field -> getFieldDefinition(fieldsContainer, field.getName()) != null)
        .collect(Collectors.toList());
  }

  @Override
  public GraphQLInputObjectField getFieldDefinition(GraphQLInputFieldsContainer fieldsContainer, String fieldName) {
    GraphQLInputObjectField field = fieldsContainer.getFieldDefinition(fieldName);
    for (GraphqlFieldVisibility visibility : visibilities) {
      if (field == null) {
        return null;
      }
      field = visibility.getFieldDefinition(fieldsContainer, fieldName);
    }
    return field;
  }

}
