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

package org.opencastproject.kernel.rest;

import org.apache.cxf.jaxrs.openapi.OpenApiCustomizer;

import java.util.Map;

import javax.ws.rs.core.MediaType;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.RequestBody;

/**
 * Adjusts the generated OpenAPI document where the swagger reader cannot work out the right information from the
 * JAX-RS annotations alone.
 *
 * <p>
 * Most Opencast endpoints take {@code @FormParam} parameters without declaring {@code @Consumes}. The swagger reader
 * turns these into an inline object schema, but, lacking a consumed media type, publishes it as {@code *}{@code /*}.
 * Since the server reads these values from a form, this customizer relabels such request bodies as
 * {@code application/x-www-form-urlencoded}.
 * </p>
 * <p>
 * Only request bodies that offer {@code *}{@code /*} as their sole media type and consist of an inline object schema
 * with named properties are touched. Bodies derived from an entity parameter are different: swagger references the
 * entity's type ({@code $ref}), describes a map ({@code additionalProperties}) or a primitive type. Media types set
 * explicitly through {@code @Consumes} or {@code @RequestBody} are never changed.
 * </p>
 */
public class OpencastOpenApiCustomizer extends OpenApiCustomizer {

  private static final String ANY_MEDIA_TYPE = MediaType.WILDCARD;
  private static final String FORM_MEDIA_TYPE = MediaType.APPLICATION_FORM_URLENCODED;

  @Override
  public void customize(final OpenAPI openApi) {
    super.customize(openApi);
    relabelFormRequestBodies(openApi);
  }

  /**
   * Relabels request bodies generated from form parameters. Idempotent, as the document may be customized more than
   * once.
   *
   * @param openApi
   *          the generated document, modified in place
   */
  static void relabelFormRequestBodies(final OpenAPI openApi) {
    if (openApi == null || openApi.getPaths() == null) {
      return;
    }
    for (final PathItem pathItem : openApi.getPaths().values()) {
      for (final Operation operation : pathItem.readOperations()) {
        relabelFormRequestBody(operation.getRequestBody());
      }
    }
  }

  private static void relabelFormRequestBody(final RequestBody requestBody) {
    if (requestBody == null) {
      return;
    }
    final Content content = requestBody.getContent();
    if (content == null || content.size() != 1 || !content.containsKey(ANY_MEDIA_TYPE)) {
      return;
    }
    final io.swagger.v3.oas.models.media.MediaType anyMediaType = content.get(ANY_MEDIA_TYPE);
    if (!isFormSchema(anyMediaType.getSchema())) {
      return;
    }
    content.remove(ANY_MEDIA_TYPE);
    content.addMediaType(FORM_MEDIA_TYPE, anyMediaType);
  }

  @SuppressWarnings("rawtypes")
  private static boolean isFormSchema(final Schema schema) {
    if (schema == null || schema.get$ref() != null || schema.getAdditionalProperties() != null) {
      return false;
    }
    final Map properties = schema.getProperties();
    return "object".equals(schema.getType()) && properties != null && !properties.isEmpty();
  }
}
