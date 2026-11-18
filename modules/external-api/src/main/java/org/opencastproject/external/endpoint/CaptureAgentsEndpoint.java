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
package org.opencastproject.external.endpoint;

import static org.opencastproject.external.util.CaptureAgentUtils.generateJsonAgent;

import org.opencastproject.capture.admin.api.Agent;
import org.opencastproject.capture.admin.api.CaptureAgentStateService;
import org.opencastproject.external.common.ApiMediaType;
import org.opencastproject.external.common.ApiResponseBuilder;

import com.google.gson.JsonArray;

import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

@Path("/api/agents")
@Produces({ ApiMediaType.JSON, ApiMediaType.VERSION_1_1_0, ApiMediaType.VERSION_1_2_0, ApiMediaType.VERSION_1_3_0,
            ApiMediaType.VERSION_1_4_0, ApiMediaType.VERSION_1_5_0, ApiMediaType.VERSION_1_6_0,
            ApiMediaType.VERSION_1_7_0, ApiMediaType.VERSION_1_8_0, ApiMediaType.VERSION_1_9_0,
            ApiMediaType.VERSION_1_10_0, ApiMediaType.VERSION_1_11_0, ApiMediaType.VERSION_1_12_0 })
@Tag(name = "External API")
@Tag(
    name = "External API - Capture Agents",
    description = "Provides resources and operations related to the capture agents"
)
@Component(
    immediate = true,
    service = CaptureAgentsEndpoint.class,
    property = {
        "service.description=External API - Capture Agents Endpoint",
        "opencast.service.type=org.opencastproject.external.agents",
        "opencast.service.path=/api/agents"
    }
)
@JaxrsResource
public class CaptureAgentsEndpoint {

  /** The logging facility */
  private static final Logger logger = LoggerFactory.getLogger(CaptureAgentsEndpoint.class);

  /** The capture agent service */
  private CaptureAgentStateService agentStateService;

  /** OSGi DI */
  public CaptureAgentStateService getAgentStateService() {
    return agentStateService;
  }

  /** OSGi DI */
  @Reference
  public void setAgentStateService(CaptureAgentStateService agentStateService) {
    this.agentStateService = agentStateService;
  }


  /** OSGi activation method */
  @Activate
  void activate(ComponentContext cc) {
    logger.info("Activating External API - Capture Agents Endpoint");
  }

  @GET
  @Path("{agentId}")
  @Operation(
      summary = "Get a capture agent",
      description = "Returns a single capture agent."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The agent is returned."),
      @ApiResponse(responseCode = "404", description = "The specified agent does not exist.")
  })
  public Response getAgent(
      @HeaderParam("Accept") String acceptHeader,
      @Parameter(description = "The agent id", required = true)
      @PathParam("agentId") String id
  ) throws Exception {
    final Agent agent = agentStateService.getAgent(id);

    if (agent == null) {
      return ApiResponseBuilder.notFound("Cannot find an agent with id '%s'.", id);
    }

    return ApiResponseBuilder.Json.ok(acceptHeader, generateJsonAgent(agent));
  }

  @GET
  @Path("/")
  @Operation(
      summary = "Get capture agents",
      description = "Returns a list of agents."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "A (potentially empty) list of agents is returned.")
  })
  public Response getAgents(
      @HeaderParam("Accept") String acceptHeader,
      @Parameter(description = "The index of the first result to return.")
      @QueryParam("offset") Integer offset,
      @Parameter(description = "The maximum number of results to return for a single request.")
      @QueryParam("limit") Integer limit
  ) {

    List<Agent> agents = new ArrayList<>(agentStateService.getKnownAgents().values());

    // Apply offset
    if (offset != null && offset > 0) {
      agents = agents.subList(Math.min(offset, agents.size()), agents.size());
    }

    // Apply limit
    if (limit != null && limit > 0) {
      agents = agents.subList(0, Math.min(limit, agents.size()));
    }

    JsonArray agentsJSON = new JsonArray();
    for (Agent a : agents) {
      agentsJSON.add(generateJsonAgent(a));
    }

    return ApiResponseBuilder.Json.ok(acceptHeader, agentsJSON);
  }


}
