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

package org.opencastproject.engage.ui;


import org.opencastproject.security.api.Organization;
import org.opencastproject.security.api.SecurityService;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * This REST endpoint redirects users to the currently configured default player, allowing the default to be changed
 * without re-publishing all events.
 */
@Path("/play")
@Tag(
    name = "Configurable Player Endpoint",
    description = "This service redirects to configured players."
)
@Component(
    immediate = true,
    service = PlayerRedirect.class,
    property = {
        "service.description=Configurable Player Endpoint",
        "opencast.service.type=org.opencastproject.engage.ui.player.redirect",
        "opencast.service.path=/play"
    }
)
@JaxrsResource
public class PlayerRedirect {

  private static final Logger logger = LoggerFactory.getLogger(PlayerRedirect.class);

  private static final String PLAYER_DEFAULT = "/paella8/ui/watch.html?id=#{id}";

  private SecurityService securityService;

  @Reference
  protected void setSecurityService(SecurityService securityService) {
    this.securityService = securityService;
  }

  @GET
  @Path("/{id:.+}")
  @Operation(
      summary = "Redirect to the player",
      description = "Redirects to the player configured for the organization (organization property \"player\", "
          + "Paella 8 by default) and passes on the query parameters."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "307", description = "Redirect to the player of the event.")
  })
  public Response redirect(
      @Parameter(description = "The event identifier", required = true)
      @PathParam("id") String id,
      @Context UriInfo uriInfo
  ) {
    final Organization org = securityService.getOrganization();
    final String playerPath = Objects.toString(org.getProperties().get("player"), PLAYER_DEFAULT)
            .replace("#{id}", URLEncoder.encode(id, StandardCharsets.UTF_8));

    final UriBuilder uriBuilder = UriBuilder.fromUri(playerPath);
    for (Map.Entry<String, List<String>> entry : uriInfo.getQueryParameters().entrySet()) {
      uriBuilder.queryParam(entry.getKey(), entry.getValue().toArray());
    }

    final String finalPath = uriBuilder.build().toString();
    logger.debug("redirecting to player: {}", finalPath);
    return Response
            .status(Response.Status.TEMPORARY_REDIRECT)
            .header("location", finalPath)
            .build();
  }
}
