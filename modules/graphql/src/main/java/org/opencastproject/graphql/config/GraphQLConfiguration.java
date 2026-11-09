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

package org.opencastproject.graphql.config;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Modified;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

@Component(
    immediate = true,
    service = GraphQLConfiguration.class,
    configurationPid = "org.opencastproject.graphql"
)
public class GraphQLConfiguration {

  private volatile Config config;

  private volatile Set<String> corsAllowedOrigins = Set.of();

  public @interface Config {
    String event_preview_subtype() default "preview";
    String event_retract_workflow_id() default "delete";

    /** Comma separated list of origins that may call the API from a browser. Empty disables CORS. */
    String cors_allowed_origins() default "";

  }

  @Activate
  @Modified
  protected void activate(final Config config) {
    this.config = config;
    this.corsAllowedOrigins = Arrays.stream(config.cors_allowed_origins().split(","))
        .map(String::trim)
        .filter(origin -> !origin.isEmpty())
        .collect(Collectors.toUnmodifiableSet());
  }

  public String eventPreviewSubtype() {
    return config.event_preview_subtype();
  }

  public String eventRetractWorkflowId() {
    return config.event_retract_workflow_id();
  }

  /**
   * @return The origins allowed to make cross-origin browser requests, or {@code *} to allow any origin.
   */
  public Set<String> corsAllowedOrigins() {
    return corsAllowedOrigins;
  }

}
