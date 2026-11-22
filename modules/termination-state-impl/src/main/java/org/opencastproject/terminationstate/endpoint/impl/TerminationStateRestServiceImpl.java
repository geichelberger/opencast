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
package org.opencastproject.terminationstate.endpoint.impl;


import org.opencastproject.terminationstate.api.TerminationStateService;
import org.opencastproject.terminationstate.endpoint.api.TerminationStateRestService;

import com.google.gson.JsonObject;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

@Path("/termination")
@Tag(
    name = "Termination State Service",
    description = "When put into a termination 'wait' state, this service stops the node accepting further jobs,"
        + " and once any running jobs complete will change termination to 'ready'."
        + " NOTE: The service does not actually shut down the node or instance."
)
@Component(
    immediate = true,
    service = TerminationStateRestServiceImpl.class,
    property = {
        "service.description=Termination State Rest Service",
        "opencast.service.type=org.opencastproject.terminationstate.impl",
        "opencast.service.path=/termination"
    }
)
@JaxrsResource
public class TerminationStateRestServiceImpl implements TerminationStateRestService {

  private static final Logger logger = LoggerFactory.getLogger(TerminationStateRestServiceImpl.class);

  private TerminationStateService service;

  @Override
  @GET
  @Path("/state")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the termination state",
      description = "Returns the Termination State as JSON. Possible termination states are none, wait and ready."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "A JSON representation of the termination state."),
      @ApiResponse(responseCode = "503", description = "The Termination State Service is disabled or unavailable")
  })
  public Response getState() {
    if (service != null) {
      JsonObject json = new JsonObject();
      String state = service.getState().toString();
      json.addProperty("state", state);
      return Response.ok(json.toString()).build();
    } else {
      logger.error("TerminationStateService is not available");
      return Response.status(Response.Status.SERVICE_UNAVAILABLE).build();
    }
  }

  @Override
  @PUT
  @Path("/state")
  @Operation(
      summary = "Set the termination state",
      description = "Set the termination state. The only permissable values are 'none', 'wait' or 'ready'"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "The termination state has been set"),
      @ApiResponse(responseCode = "400", description = "The state was not valid"),
      @ApiResponse(responseCode = "503", description = "The Termination State Service is disabled or unavailable")
  })
  public Response setState(
      @Parameter(
          description = "The termination state, one of 'none', 'wait' or 'ready'",
          required = true,
          schema = @Schema(example = "wait")
      )
      @FormParam("state") String state
  ) {
    if (service != null) {
      TerminationStateService.TerminationState tState;
      switch (state) {
        case "none":
          tState = TerminationStateService.TerminationState.NONE;
          break;
        case "wait":
          tState = TerminationStateService.TerminationState.WAIT;
          break;
        case "ready":
          tState = TerminationStateService.TerminationState.READY;
          break;
        default:
          logger.error("state {} is invalid", state);
          return Response.status(Response.Status.BAD_REQUEST).build();
      }

      service.setState(tState);
      return Response.noContent().build();
    }

    logger.error("AWS Autoscaling Termination State Serice is not available");
    return Response.status(Response.Status.SERVICE_UNAVAILABLE).build();
  }

  /**
   OSGI injection callback
   @param service termination state service instance
   */
  @Reference(
      target = "(&(vendor.name=opencast)(vendor.service=basic))"
  )
  public void setService(TerminationStateService service) {
    this.service = service;
  }
}
