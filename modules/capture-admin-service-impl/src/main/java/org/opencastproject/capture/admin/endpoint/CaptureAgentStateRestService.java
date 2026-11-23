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

package org.opencastproject.capture.admin.endpoint;

import static org.opencastproject.capture.admin.api.AgentState.KNOWN_STATES;

import org.opencastproject.capture.admin.api.Agent;
import org.opencastproject.capture.admin.api.AgentStateUpdate;
import org.opencastproject.capture.admin.api.CaptureAgentStateService;
import org.opencastproject.capture.admin.impl.RecordingStateUpdate;
import org.opencastproject.scheduler.api.Recording;
import org.opencastproject.scheduler.api.SchedulerException;
import org.opencastproject.scheduler.api.SchedulerService;
import org.opencastproject.util.NotFoundException;
import org.opencastproject.util.PropertiesResponse;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.DELETE;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * The REST endpoint for the capture agent service on the capture device
 */
@Path("/capture-admin")
@Tag(
    name = "Capture Admin Service",
    description = "This service is a registry of capture agents and their recordings."
)
@Component(
    immediate = true,
    service = CaptureAgentStateRestService.class,
    property = {
        "service.description=Capture Agent Admin REST Endpoint",
        "opencast.service.type=org.opencastproject.capture.admin",
        "opencast.service.path=/capture-admin"
    }
)
@JaxrsResource
public class CaptureAgentStateRestService {

  private static final Logger logger = LoggerFactory.getLogger(CaptureAgentStateRestService.class);
  private CaptureAgentStateService service;
  private SchedulerService schedulerService;

  /**
   * Callback from OSGi that is called when this service is activated.
   *
   * @param cc
   *          OSGi component context
   */
  @Activate
  public void activate(ComponentContext cc) {
  }

  @Reference(
      cardinality = ReferenceCardinality.OPTIONAL,
      policy = ReferencePolicy.DYNAMIC,
      unbind = "unsetService"
  )
  public void setService(CaptureAgentStateService service) {
    this.service = service;
  }

  public void unsetService(CaptureAgentStateService service) {
    if (this.service == service) {
      this.service = null;
    }
  }

  @Reference
  public void setSchedulerService(SchedulerService schedulerService) {
    this.schedulerService = schedulerService;
  }

  public CaptureAgentStateRestService() {
  }

  @GET
  @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
  @Path("agents/{name}.{format:xml|json}")
  @Operation(
      summary = "Get the state of a capture agent",
      description = "Return the state of a given capture agent"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The state of the capture agent."),
      @ApiResponse(responseCode = "404", description = "The agent does not exist."),
      @ApiResponse(responseCode = "503", description = "The capture agent state service is not available.")
  })
  public Response getAgentState(
      @Parameter(description = "Name of the capture agent", required = true)
      @PathParam("name") String agentName,
      @Parameter(description = "The output format (json or xml) of the response body.", required = true)
      @PathParam("format") String format
  ) throws NotFoundException {
    if (service == null) {
      return Response.serverError().status(Response.Status.SERVICE_UNAVAILABLE).build();
    }

    Agent ret = service.getAgent(agentName);
    logger.debug("Returning agent state for {}", agentName);
    if ("json".equals(format)) {
      return Response.ok(new AgentStateUpdate(ret)).type(MediaType.APPLICATION_JSON).build();
    } else {
      return Response.ok(new AgentStateUpdate(ret)).type(MediaType.APPLICATION_XML).build();
    }
  }

  @POST
  @Produces(MediaType.TEXT_HTML)
  @Path("agents/{name}")
  // Todo: Capture agent may send an optional FormParam containing it's configured address.
  // If this exists don't use request.getRemoteHost() for the URL
  @Operation(
      summary = "Set the state of a capture agent",
      description = "Set the status of a given capture agent"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "{agentName} set to {state}"),
      @ApiResponse(responseCode = "400", description = "{state} is empty or not known"),
      @ApiResponse(responseCode = "503", description = "Capture agent state service not available")
  })
  public Response setAgentState(
      @Context HttpServletRequest request,
      @Parameter(description = "Address of the agent")
      @FormParam("address") String address,
      @Parameter(description = "Name of the capture agent", required = true)
      @PathParam("name") String agentName,
      @Parameter(
          description = "The state of the capture "
              + "agent. Known states are: idle, shutting_down, capturing, uploading, unknown, offline, error",
          required = true
      )
      @FormParam("state") String state
  ) throws NotFoundException {
    if (service == null) {
      return Response.serverError().status(Response.Status.SERVICE_UNAVAILABLE).build();
    }

    if (!KNOWN_STATES.contains(state)) {
      logger.debug("'{}' is not a valid state", state);
      return Response.status(javax.ws.rs.core.Response.Status.BAD_REQUEST).build();
    }

    if (StringUtils.isEmpty(address)) {
      address = request.getRemoteHost();
    }

    logger.debug("Agents URL: {}", address);

    boolean agentStateUpdated = service.setAgentState(agentName, state);
    boolean agentUrlUpdated = service.setAgentUrl(agentName, address);

    if (!agentStateUpdated && !agentUrlUpdated) {
      logger.debug("{}'s state '{}' and url '{}' has not changed, nothing has been updated", agentName, state, address);
      return Response.ok().build();
    }
    logger.debug("{}'s state successfully set to {}", agentName, state);
    return Response.ok(agentName + " set to " + state).build();
  }

  @DELETE
  @Path("agents/{name}")
  @Produces(MediaType.TEXT_HTML)
  @Operation(
      summary = "Remove a capture agent",
      description = "Remove record of a given capture agent"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "{agentName} removed"),
      @ApiResponse(responseCode = "404", description = "The agent {agentname} does not exist"),
      @ApiResponse(responseCode = "503", description = "The capture agent state service is not available.")
  })
  public Response removeAgent(
      @Parameter(description = "Name of the capture agent", required = true)
      @PathParam("name") String agentName
  ) throws NotFoundException {
    if (service == null) {
      return Response.serverError().status(Response.Status.SERVICE_UNAVAILABLE).build();
    }

    service.removeAgent(agentName);

    logger.debug("The agent {} was successfully removed", agentName);
    return Response.ok(agentName + " removed").build();
  }

  @GET
  @Produces({ MediaType.TEXT_XML, MediaType.APPLICATION_JSON })
  @Path("agents.{type:xml|json}")
  @Operation(
      summary = "List the known capture agents",
      description = "Return all of the known capture agents on the system"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The known capture agents and their states."),
      @ApiResponse(responseCode = "503", description = "The capture agent state service is not available.")
  })
  public Response getKnownAgents(
      @Parameter(description = "The Document type", required = true)
      @PathParam("type") String type
  ) {
    if (service == null) {
      return Response.serverError().status(Response.Status.SERVICE_UNAVAILABLE).build();
    }

    logger.debug("Returning list of known agents...");
    LinkedList<AgentStateUpdate> update = new LinkedList<AgentStateUpdate>();
    Map<String, Agent> data = service.getKnownAgents();
    logger.debug("Agents: {}", data);
    // Run through and build a map of updates (rather than states)
    for (Entry<String, Agent> e : data.entrySet()) {
      update.add(new AgentStateUpdate(e.getValue()));
    }

    if ("json".equals(type)) {
      return Response.ok(new AgentStateUpdateList(update)).type(MediaType.APPLICATION_JSON).build();
    } else {
      return Response.ok(new AgentStateUpdateList(update)).type(MediaType.TEXT_XML).build();
    }
  }

  @GET
  @Produces({ MediaType.TEXT_XML, MediaType.APPLICATION_JSON })
  @Path("agents/{name}/capabilities.{type:xml|json}")
  @Operation(
      summary = "Get the capabilities of a capture agent",
      description = "Return the capabilities of a given capture agent"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the agent capabilities"),
      @ApiResponse(responseCode = "404", description = "The agent {name} does not exist in the system"),
      @ApiResponse(responseCode = "503", description = "The capture agent state service is not available.")
  })
  public Response getCapabilities(
      @Parameter(description = "Name of the capture agent", required = true)
      @PathParam("name") String agentName,
      @Parameter(description = "The Document type", required = true)
      @PathParam("type") String type
  ) throws NotFoundException {
    if (service == null) {
      return Response.serverError().status(Response.Status.SERVICE_UNAVAILABLE).build();
    }

    PropertiesResponse r = new PropertiesResponse(service.getAgentCapabilities(agentName));
    if ("json".equals(type)) {
      return Response.ok(r).type(MediaType.APPLICATION_JSON).build();
    } else {
      return Response.ok(r).type(MediaType.TEXT_XML).build();
    }
  }

  @GET
  @Produces({ MediaType.TEXT_XML, MediaType.APPLICATION_JSON })
  @Path("agents/{name}/configuration.{type:xml|json}")
  @Operation(
      summary = "Get the configuration of a capture agent",
      description = "Return the configuration of a given capture agent"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML or JSON representation of the agent configuration"),
      @ApiResponse(responseCode = "404", description = "The agent {name} does not exist in the system"),
      @ApiResponse(responseCode = "503", description = "The capture agent state service is not available.")
  })
  public Response getConfiguration(
      @Parameter(description = "Name of the capture agent", required = true)
      @PathParam("name") String agentName,
      @Parameter(description = "The Document type", required = true)
      @PathParam("type") String type
  ) throws NotFoundException {
    if (service == null) {
      return Response.serverError().status(Response.Status.SERVICE_UNAVAILABLE).build();
    }

    PropertiesResponse r = new PropertiesResponse(service.getAgentConfiguration(agentName));
    logger.debug("Returning configuration for the agent {}", agentName);

    if ("json".equals(type)) {
      return Response.ok(r).type(MediaType.APPLICATION_JSON).build();
    } else {
      return Response.ok(r).type(MediaType.TEXT_XML).build();
    }
  }

  @POST
  @Produces({ MediaType.TEXT_XML, MediaType.APPLICATION_JSON })
  @Path("agents/{name}/configuration")
  @Operation(
      summary = "Set the configuration of a capture agent",
      description = "Set the configuration of a given capture agent, registering it if it does not exist"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML or JSON representation of the agent configuration"),
      @ApiResponse(
          responseCode = "400",
          description = "The configuration format is incorrect OR the agent name is blank or null"
      ),
      @ApiResponse(responseCode = "503", description = "The capture agent state service is not available.")
  })
  public Response setConfiguration(
      @Parameter(description = "Name of the capture agent", required = true)
      @PathParam("name") String agentName,
      @Parameter(
          description = "An XML or JSON representation of the capabilities. XML as specified in "
              + "http://java.sun.com/dtd/properties.dtd (friendly names as keys, device locations as corresponding "
              + "values)",
          required = true
      )
      @FormParam("configuration") String configuration
  ) {
    if (service == null) {
      return Response.serverError().status(Response.Status.SERVICE_UNAVAILABLE).build();
    }

    if (StringUtils.isBlank(configuration)) {
      logger.debug("The configuration data cannot be blank");
      return Response.serverError().status(Response.Status.BAD_REQUEST).build();
    }

    Properties caps;

    if (Strings.CS.startsWith(configuration, "{")) {
      // JSON
      Gson gson = new Gson();
      try {
        caps = gson.fromJson(configuration, Properties.class);
        if (!service.setAgentConfiguration(agentName, caps)) {
          logger.debug("'{}''s configuration has not been updated because nothing has been changed", agentName);
        }
        return Response.ok(gson.toJson(caps)).type(MediaType.APPLICATION_JSON).build();
      } catch (JsonSyntaxException e) {
        logger.debug("Exception when deserializing capabilities: {}", e.getMessage());
        return Response.status(javax.ws.rs.core.Response.Status.BAD_REQUEST).build();
      }

    } else {
      // XML
      caps = new Properties();
      ByteArrayInputStream bais = null;
      try {
        bais = new ByteArrayInputStream(configuration.getBytes());
        caps.loadFromXML(bais);
        if (!service.setAgentConfiguration(agentName, caps)) {
          logger.debug("'{}''s configuration has not been updated because nothing has been changed", agentName);
        }

        // Prepares the value to return
        PropertiesResponse r = new PropertiesResponse(caps);
        logger.debug("{}'s configuration updated", agentName);
        return Response.ok(r).type(MediaType.TEXT_XML).build();
      } catch (IOException e) {
        logger.debug("Unexpected I/O Exception when unmarshalling the capabilities: {}", e.getMessage());
        return Response.status(javax.ws.rs.core.Response.Status.BAD_REQUEST).build();
      } finally {
        IOUtils.closeQuietly(bais);
      }
    }
  }

  @GET
  @Produces({ MediaType.TEXT_XML, MediaType.APPLICATION_JSON })
  @Path("recordings/{id}.{type:xml|json|}")
  @Operation(
      summary = "Get the state of a recording",
      description = "Return the state of a given recording"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returns the state of the recording with the correct id"),
      @ApiResponse(responseCode = "404", description = "The recording with the specified ID does not exist"),
      @ApiResponse(responseCode = "500", description = "The state of the recording could not be retrieved.")
  })
  public Response getRecordingState(
      @Parameter(description = "The ID of a given recording", required = true)
      @PathParam("id") String id,
      @Parameter(description = "The Documenttype", required = true)
      @PathParam("type") String type
  ) throws NotFoundException {
    try {
      Recording rec = schedulerService.getRecordingState(id);

      logger.debug("Submitting state for recording {}", id);
      if ("json".equals(type)) {
        return Response.ok(new RecordingStateUpdate(rec)).type(MediaType.APPLICATION_JSON).build();
      } else {
        return Response.ok(new RecordingStateUpdate(rec)).type(MediaType.TEXT_XML).build();
      }
    } catch (SchedulerException e) {
      logger.debug("Unable to get recording state of {}", id, e);
      return Response.serverError().build();
    }
  }

  @POST
  @Path("recordings/{id}")
  @Operation(
      summary = "Set the state of a recording",
      description = "Set the status of an existing recording. The recording must correspond to a scheduled "
          + "event; unknown identifiers return 404."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "{id} set to {state}"),
      @ApiResponse(responseCode = "400", description = "{id} or {state} is empty or {state} is not known"),
      @ApiResponse(responseCode = "404", description = "Recording with {id} could not be found"),
      @ApiResponse(responseCode = "500", description = "The state of the recording could not be set.")
  })
  public Response setRecordingState(
      @Parameter(description = "The ID of a given recording", required = true)
      @PathParam("id") String id,
      @Parameter(
          description = "The state of the recording. Known states: unknown, capturing, capture_finished, "
              + "capture_error, manifest, manifest_error, manifest_finished, compressing, compressing_error, "
              + "uploading, upload_finished, upload_error.",
          required = true
      )
      @FormParam("state") String state
  ) throws NotFoundException {
    if (StringUtils.isEmpty(id) || StringUtils.isEmpty(state)) {
      return Response.serverError().status(Response.Status.BAD_REQUEST).build();
    }

    try {
      if (schedulerService.updateRecordingState(id, state)) {
        return Response.ok(id + " set to " + state).build();
      } else {
        return Response.status(Response.Status.BAD_REQUEST).build();
      }
    } catch (SchedulerException e) {
      logger.debug("Unable to set recording state of {}", id, e);
      return Response.serverError().build();
    }
  }

  @DELETE
  @Path("recordings/{id}")
  @Operation(
      summary = "Remove a recording",
      description = "Remove record of a given recording"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "{id} removed"),
      @ApiResponse(responseCode = "400", description = "{id} is empty"),
      @ApiResponse(responseCode = "404", description = "Recording with {id} could not be found"),
      @ApiResponse(responseCode = "500", description = "The recording could not be removed.")
  })
  public Response removeRecording(
      @Parameter(description = "The ID of a given recording", required = true)
      @PathParam("id") String id
  ) throws NotFoundException {
    if (StringUtils.isEmpty(id)) {
      return Response.serverError().status(Response.Status.BAD_REQUEST).build();
    }

    try {
      schedulerService.removeRecording(id);
      return Response.ok(id + " removed").build();
    } catch (SchedulerException e) {
      logger.debug("Unable to remove recording with id '{}'", id, e);
      return Response.serverError().build();
    }
  }

  @GET
  @Produces(MediaType.TEXT_XML)
  @Path("recordings")
  @Operation(
      summary = "List all recordings",
      description = "Return all registered recordings and their state"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returns all known recordings."),
      @ApiResponse(responseCode = "500", description = "The recordings could not be retrieved.")
  })
  public List<RecordingStateUpdate> getAllRecordings() {
    try {
      LinkedList<RecordingStateUpdate> update = new LinkedList<RecordingStateUpdate>();
      Map<String, Recording> data = schedulerService.getKnownRecordings();
      // Run through and build a map of updates (rather than states)
      for (Entry<String, Recording> e : data.entrySet()) {
        update.add(new RecordingStateUpdate(e.getValue()));
      }
      return update;
    } catch (SchedulerException e) {
      logger.debug("Unable to get all recordings", e);
      throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

}
