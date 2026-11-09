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

package org.opencastproject.graphql.provider;

import graphql.schema.GraphQLCodeRegistry;

/**
 * Extends the code registry of the schema, e.g. with data fetchers for fields added by a {@link GraphQLQueryProvider}
 * or {@link GraphQLMutationProvider}. Providers are applied in turn; each gets the registry built so far.
 *
 * <p>A provider can also replace data fetchers of existing fields, including the access checks added by
 * {@code @RolesAllowed}, so only register trusted providers.
 */
public interface GraphQLCodeRegistryProvider extends GraphQLProvider {

  /**
   * @param codeRegistry the code registry built so far
   * @return a builder for the extended registry, e.g. {@code GraphQLCodeRegistry.newCodeRegistry(codeRegistry)},
   *     or {@code null} to leave it unchanged
   */
  GraphQLCodeRegistry.Builder getCodeRegistry(GraphQLCodeRegistry codeRegistry);

}
