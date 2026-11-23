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

package org.opencastproject.scheduler.endpoint;

import static javax.servlet.http.HttpServletResponse.SC_BAD_REQUEST;
import static org.apache.commons.lang3.exception.ExceptionUtils.getMessage;
import static org.opencastproject.capture.CaptureParameters.AGENT_REGISTRATION_TYPE;
import static org.opencastproject.capture.CaptureParameters.AGENT_REGISTRATION_TYPE_ADHOC;
import static org.opencastproject.metadata.dublincore.DublinCore.PROPERTY_CREATED;
import static org.opencastproject.metadata.dublincore.DublinCore.PROPERTY_SPATIAL;
import static org.opencastproject.metadata.dublincore.DublinCore.PROPERTY_TEMPORAL;
import static org.opencastproject.metadata.dublincore.DublinCore.PROPERTY_TITLE;
import static org.opencastproject.util.RestUtil.generateErrorResponse;

import org.opencastproject.capture.admin.api.Agent;
import org.opencastproject.capture.admin.api.AgentState;
import org.opencastproject.capture.admin.api.CaptureAgentStateService;
import org.opencastproject.mediapackage.Catalog;
import org.opencastproject.mediapackage.MediaPackage;
import org.opencastproject.mediapackage.MediaPackageBuilderFactory;
import org.opencastproject.mediapackage.MediaPackageElement;
import org.opencastproject.mediapackage.MediaPackageElementBuilderFactory;
import org.opencastproject.mediapackage.MediaPackageElementFlavor;
import org.opencastproject.mediapackage.MediaPackageElements;
import org.opencastproject.mediapackage.MediaPackageException;
import org.opencastproject.mediapackage.MediaPackageParser;
import org.opencastproject.mediapackage.MediaPackageSupport;
import org.opencastproject.metadata.dublincore.DCMIPeriod;
import org.opencastproject.metadata.dublincore.DublinCore;
import org.opencastproject.metadata.dublincore.DublinCoreCatalog;
import org.opencastproject.metadata.dublincore.DublinCoreUtil;
import org.opencastproject.metadata.dublincore.DublinCores;
import org.opencastproject.metadata.dublincore.EncodingSchemeUtils;
import org.opencastproject.metadata.dublincore.Precision;
import org.opencastproject.rest.RestConstants;
import org.opencastproject.scheduler.api.Recording;
import org.opencastproject.scheduler.api.SchedulerConflictException;
import org.opencastproject.scheduler.api.SchedulerException;
import org.opencastproject.scheduler.api.SchedulerService;
import org.opencastproject.scheduler.api.TechnicalMetadata;
import org.opencastproject.scheduler.impl.CaptureNowProlongingService;
import org.opencastproject.security.api.UnauthorizedException;
import org.opencastproject.systems.OpencastConstants;
import org.opencastproject.util.DateTimeSupport;
import org.opencastproject.util.GsonUtil;
import org.opencastproject.util.NotFoundException;
import org.opencastproject.util.RestUtil;
import org.opencastproject.util.UrlSupport;
import org.opencastproject.workspace.api.Workspace;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializer;

import net.fortuna.ical4j.model.property.RRule;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.URI;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.TimeZone;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.DELETE;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.Response.Status;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * REST Endpoint for Scheduler Service
 */
@Path("/recordings")
@Tag(
    name = "Scheduler Service",
    description = "This service creates, edits and retrieves and helps managing scheduled capture events."
)
@Component(
    immediate = true,
    service = SchedulerRestService.class,
    property = {
        "service.description=Scheduler REST Endpoint",
        "opencast.service.type=org.opencastproject.scheduler",
        "opencast.service.path=/recordings"
    }
)
@JaxrsResource
public class SchedulerRestService {

  private static final Logger logger = LoggerFactory.getLogger(SchedulerRestService.class);

  /** Key for the default workflow definition in config.properties */
  private static final String DEFAULT_WORKFLOW_DEFINITION = "org.opencastproject.workflow.default.definition";

  private SchedulerService service;
  private CaptureAgentStateService agentService;
  private CaptureNowProlongingService prolongingService;
  private Workspace workspace;

  private final Gson gson = new Gson();
  private final Gson gsonTimestamp = new GsonBuilder()
      .registerTypeAdapter(
          Date.class,
          (JsonSerializer<Date>) (date, type, jsonSerializationContext) -> new JsonPrimitive(date.getTime()))
      .create();

  private String defaultWorkflowDefinitionId;

  protected String serverUrl = UrlSupport.DEFAULT_BASE_URL;
  protected String serviceUrl = null;

  /**
   * Method to set the service this REST endpoint uses
   *
   * @param service
   */
  @Reference(
      policy = ReferencePolicy.DYNAMIC,
      unbind = "unsetService"
  )
  public void setService(SchedulerService service) {
    this.service = service;
  }

  /**
   * Method to unset the service this REST endpoint uses
   *
   * @param service
   */
  public void unsetService(SchedulerService service) {
    if (this.service == service) {
      this.service = null;
    }
  }

  /**
   * Method to set the prolonging service this REST endpoint uses
   *
   * @param prolongingService
   */
  @Reference(
      policy = ReferencePolicy.DYNAMIC,
      unbind = "unsetProlongingService"
  )
  public void setProlongingService(CaptureNowProlongingService prolongingService) {
    this.prolongingService = prolongingService;
  }

  /**
   * Method to unset the prolonging service this REST endpoint uses
   *
   * @param prolongingService
   */
  public void unsetProlongingService(CaptureNowProlongingService prolongingService) {
    if (this.prolongingService == prolongingService) {
      this.prolongingService = null;
    }
  }

  /**
   * Method to set the capture agent state service this REST endpoint uses
   *
   * @param agentService
   */
  @Reference(
      cardinality = ReferenceCardinality.OPTIONAL,
      policy = ReferencePolicy.DYNAMIC,
      unbind = "unsetCaptureAgentStateService"
  )
  public void setCaptureAgentStateService(CaptureAgentStateService agentService) {
    this.agentService = agentService;
  }

  /**
   * Method to unset the capture agent state service this REST endpoint uses
   *
   * @param agentService
   */
  public void unsetCaptureAgentStateService(CaptureAgentStateService agentService) {
    if (this.agentService == agentService) {
      this.agentService = null;
    }
  }

  /**
   * Method to set the workspace this REST endpoint uses
   *
   * @param workspace
   */
  @Reference
  public void setWorkspace(Workspace workspace) {
    this.workspace = workspace;
  }

  /**
   * The method that will be called, if the service will be activated
   *
   * @param cc
   *          The ComponentContext of this service
   */
  @Activate
  public void activate(ComponentContext cc) {
    // Get the configured server URL
    if (cc != null) {
      String ccServerUrl = cc.getBundleContext().getProperty(OpencastConstants.SERVER_URL_PROPERTY);
      logger.debug("configured server url is {}", ccServerUrl);
      if (ccServerUrl == null) {
        serverUrl = UrlSupport.DEFAULT_BASE_URL;
      } else {
        serverUrl = ccServerUrl;
      }
      serviceUrl = (String) cc.getProperties().get(RestConstants.SERVICE_PATH_PROPERTY);
      defaultWorkflowDefinitionId = StringUtils
              .trimToNull(cc.getBundleContext().getProperty(DEFAULT_WORKFLOW_DEFINITION));
      if (defaultWorkflowDefinitionId == null) {
        defaultWorkflowDefinitionId = "schedule-and-upload";
      }
    }
  }

  /**
   * Gets a XML with the media package for the specified event.
   *
   * @param eventId
   *          The unique ID of the event.
   * @return media package XML for the event
   */
  @GET
  @Produces(MediaType.TEXT_XML)
  @Path("{id:.+}/mediapackage.xml")
  @Operation(
      summary = "Get the media package of an event",
      description = "Retrieves media package for specified event"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "The media package of the event is in the body of the response"
      ),
      @ApiResponse(
          responseCode = "404",
          description = "Event with specified ID does not exist"
      ),
      @ApiResponse(
          responseCode = "401",
          description = "You do not have permission to read the event. Maybe you need to authenticate."
      ),
      @ApiResponse(responseCode = "500", description = "An internal error occurred.")
  })
  public Response getMediaPackageXml(
      @Parameter(
          description = "ID of event for which media package will be retrieved",
          required = true
      )
      @PathParam("id") String eventId
  ) throws UnauthorizedException {
    try {
      MediaPackage result = service.getMediaPackage(eventId);
      return Response.ok(MediaPackageParser.getAsXml(result)).build();
    } catch (NotFoundException e) {
      logger.info("Event with id '{}' does not exist.", eventId);
      return Response.status(Status.NOT_FOUND).build();
    } catch (SchedulerException e) {
      logger.error("Unable to retrieve event with id '{}': {}", eventId, getMessage(e));
      throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * Gets a XML with the Dublin Core metadata for the specified event.
   *
   * @param eventId
   *          The unique ID of the event.
   * @return Dublin Core XML for the event
   */
  @GET
  @Produces(MediaType.TEXT_XML)
  @Path("{id:.+}/dublincore.xml")
  @Operation(
      summary = "Get the Dublin Core metadata of an event as XML",
      description = "Retrieves DublinCore for specified event"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "DublinCore of event is in the body of response"
      ),
      @ApiResponse(
          responseCode = "404",
          description = "Event with specified ID does not exist"
      ),
      @ApiResponse(
          responseCode = "401",
          description = "You do not have permission to read the event. Maybe you need to authenticate."
      ),
      @ApiResponse(responseCode = "500", description = "An internal error occurred.")
  })
  public Response getDublinCoreMetadataXml(
      @Parameter(
          description = "ID of event for which DublinCore will be retrieved",
          required = true
      )
      @PathParam("id") String eventId
  ) throws UnauthorizedException {
    try {
      DublinCoreCatalog result = service.getDublinCore(eventId);
      return Response.ok(result.toXmlString()).build();
    } catch (NotFoundException e) {
      logger.info("Event with id '{}' does not exist.", eventId);
      return Response.status(Status.NOT_FOUND).build();
    } catch (UnauthorizedException e) {
      throw e;
    } catch (Exception e) {
      logger.error("Unable to retrieve event with id '{}': {}", eventId, getMessage(e));
      throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * Gets a Dublin Core metadata for the specified event as JSON.
   *
   * @param eventId
   *          The unique ID of the event.
   * @return Dublin Core JSON for the event
   */
  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("{id:.+}/dublincore.json")
  @Operation(
      summary = "Get the Dublin Core metadata of an event as JSON",
      description = "Retrieves DublinCore for specified event"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "DublinCore of event is in the body of response"
      ),
      @ApiResponse(
          responseCode = "404",
          description = "Event with specified ID does not exist"
      ),
      @ApiResponse(
          responseCode = "401",
          description = "You do not have permission to read the event. Maybe you need to authenticate."
      ),
      @ApiResponse(responseCode = "500", description = "An internal error occurred.")
  })
  public Response getDublinCoreMetadataJSON(
      @Parameter(
          description = "ID of event for which DublinCore will be retrieved",
          required = true
      )
      @PathParam("id") String eventId
  ) throws UnauthorizedException {
    try {
      DublinCoreCatalog result = service.getDublinCore(eventId);
      return Response.ok(result.toJson()).build();
    } catch (NotFoundException e) {
      logger.info("Event with id '{}' does not exist.", eventId);
      return Response.status(Status.NOT_FOUND).build();
    } catch (UnauthorizedException e) {
      throw e;
    } catch (Exception e) {
      logger.error("Unable to retrieve event with id '{}': {}", eventId, getMessage(e));
      throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * Gets a XML with the media package for the specified event.
   *
   * @param eventId
   *          The unique ID of the event.
   * @return media package XML for the event
   */
  @GET
  @Produces(MediaType.TEXT_XML)
  @Path("{id:.+}/technical.json")
  @Operation(
      summary = "Get the technical metadata of an event",
      description = "Retrieves the technical metadata for specified event"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "The technical metadata of the event is in the body of the response. The content type "
              + "is application/json, although the operation declares text/xml.",
          content = @Content(mediaType = "application/json")
      ),
      @ApiResponse(
          responseCode = "404",
          description = "Event with specified ID does not exist"
      ),
      @ApiResponse(
          responseCode = "401",
          description = "You do not have permission to read the event. Maybe you need to authenticate."
      ),
      @ApiResponse(responseCode = "500", description = "An internal error occurred.")
  })
  public Response getTechnicalMetadataJSON(
      @Parameter(
          description = "ID of event for which the technical metadata will be retrieved",
          required = true
      )
      @PathParam("id") String eventId
  ) throws UnauthorizedException {
    try {
      TechnicalMetadata metadata = service.getTechnicalMetadata(eventId);

      String state = "";
      String lastHeard = "";
      if (metadata.getRecording().isPresent()) {
        state = metadata.getRecording().get().getState();
        lastHeard = DateTimeSupport.toUTC(metadata.getRecording().get().getLastCheckinTime());
      }

      JsonArray presenters = new JsonArray();
      metadata.getPresenters().forEach(presenters::add);
      JsonObject wfProperties = new JsonObject();
      for (Entry<String, String> entry : metadata.getWorkflowProperties().entrySet()) {
        wfProperties.addProperty(entry.getKey(), entry.getValue());
      }
      JsonObject agentConfig = new JsonObject();
      for (Entry<String, String> entry : metadata.getCaptureAgentConfiguration().entrySet()) {
        agentConfig.addProperty(entry.getKey(), entry.getValue());
      }

      JsonObject json = new JsonObject();
      json.addProperty("id", metadata.getEventId());
      json.addProperty("location", metadata.getAgentId());
      json.addProperty("start", DateTimeSupport.toUTC(metadata.getStartDate().getTime()));
      json.addProperty("end", DateTimeSupport.toUTC(metadata.getEndDate().getTime()));
      json.add("presenters", presenters);
      json.add("wfProperties", wfProperties);
      json.add("agentConfig", agentConfig);
      json.addProperty("state", state);
      json.addProperty("lastHeardFrom", lastHeard);
      return RestUtil.R.ok(json);
    } catch (NotFoundException e) {
      logger.info("Event with id '{}' does not exist.", eventId);
      return Response.status(Status.NOT_FOUND).build();
    } catch (SchedulerException e) {
      logger.error("Unable to retrieve event with id '{}': {}", eventId, getMessage(e));
      throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * Gets the workflow configuration for the specified event.
   *
   * @param eventId
   *          The unique ID of the event.
   * @return the workflow configuration
   */
  @GET
  @Produces(MediaType.TEXT_PLAIN)
  @Path("{id:.+}/workflow.properties")
  @Operation(
      summary = "Get the workflow configuration of an event",
      description = "Retrieves workflow configuration for specified event"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "workflow configuration of event is in the body of response"
      ),
      @ApiResponse(
          responseCode = "404",
          description = "Event with specified ID does not exist"
      ),
      @ApiResponse(
          responseCode = "401",
          description = "You do not have permission to read the event. Maybe you need to authenticate."
      ),
      @ApiResponse(responseCode = "500", description = "An internal error occurred.")
  })
  public Response getWorkflowConfiguration(
      @Parameter(
          description = "ID of event for which workflow configuration will be retrieved",
          required = true
      )
      @PathParam("id") String eventId
  ) throws UnauthorizedException {
    try {
      Map<String, String> result = service.getWorkflowConfig(eventId);
      String serializedProperties = serializeProperties(result);
      return Response.ok(serializedProperties).build();
    } catch (NotFoundException e) {
      logger.info("Event with id '{}' does not exist.", eventId);
      return Response.status(Status.NOT_FOUND).build();
    } catch (SchedulerException e) {
      logger.error("Unable to retrieve workflow configuration for event with id '{}': {}", eventId, getMessage(e));
      throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * Gets java Properties file with technical metadata for the specified event.
   *
   * @param eventId
   *          The unique ID of the event.
   * @return Java Properties File with the metadata for the event
   */
  @GET
  @Produces(MediaType.TEXT_PLAIN)
  @Path("{id:.+}/agent.properties")
  @Operation(
      summary = "Get the capture agent properties of an event",
      description = "Retrieves Capture Agent properties for specified event"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "Capture Agent properties of event is in the body of response"
      ),
      @ApiResponse(
          responseCode = "404",
          description = "Event with specified ID does not exist"
      ),
      @ApiResponse(
          responseCode = "401",
          description = "You do not have permission to read the event. Maybe you need to authenticate."
      ),
      @ApiResponse(responseCode = "500", description = "An internal error occurred.")
  })
  public Response getCaptureAgentMetadata(
      @Parameter(
          description = "ID of event for which agent properties will be retrieved",
          required = true
      )
      @PathParam("id") String eventId
  ) throws UnauthorizedException {
    try {
      Map<String, String> result = service.getCaptureAgentConfiguration(eventId);
      String serializedProperties = serializeProperties(result);
      return Response.ok(serializedProperties).build();
    } catch (NotFoundException e) {
      logger.info("Event with id '{}' does not exist.", eventId);
      return Response.status(Status.NOT_FOUND).build();
    } catch (SchedulerException e) {
      logger.error("Unable to retrieve event with id '{}': {}", eventId, getMessage(e));
      throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   *
   * Removes the specified event. Returns true if the event was found and could be removed.
   *
   * @param eventId
   *          The unique ID of the event.
   * @return true if the event was found and could be deleted.
   */
  @DELETE
  @Path("{id:.+}")
  @Produces(MediaType.TEXT_PLAIN)
  @Operation(
      summary = "Delete an event",
      description = "Removes scheduled event with specified ID."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Event was successfully removed"),
      @ApiResponse(
          responseCode = "404",
          description = "Event with specified ID does not exist"
      ),
      @ApiResponse(
          responseCode = "401",
          description = "You do not have permission to remove the event. Maybe you need to authenticate."
      ),
      @ApiResponse(
          responseCode = "409",
          description = "Event with specified ID is locked by a transaction, unable to delete event."
      ),
      @ApiResponse(responseCode = "500", description = "An internal error occurred.")
  })
  public Response deleteEvent(
      @Parameter(description = "Event ID", required = true)
      @PathParam("id") String eventId
  ) throws UnauthorizedException {
    try {
      service.removeEvent(eventId);
      return Response.status(Response.Status.OK).build();
    } catch (NotFoundException e) {
      logger.info("Event with id '{}' does not exist.", eventId);
      return Response.status(Status.NOT_FOUND).build();
    } catch (UnauthorizedException e) {
      throw e;
    } catch (Exception e) {
      logger.error("Unable to delete event with id '{}': {}", eventId, getMessage(e));
      throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * Gets the iCalendar with all (even old) events for the specified filter.
   *
   * @param captureAgentId
   *          The ID that specifies the capture agent.
   * @param seriesId
   *          The ID that specifies series.
   *
   * @return an iCalendar
   */
  @GET
  @Produces("text/calendar")
  // NOTE: charset not supported by current jaxrs impl (is ignored), set explicitly in response
  @Path("calendars")
  @Operation(
      summary = "Get events as iCalendar",
      description = "Returns iCalendar for specified set of events"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "304",
          description = "Events were not modified since last request"
      ),
      @ApiResponse(
          responseCode = "200",
          description = "Events were modified, new calendar is in the body"
      ),
      @ApiResponse(
          responseCode = "400",
          description = "The cutoff parameter is not a valid number"
      ),
      @ApiResponse(responseCode = "500", description = "An internal error occurred.")
  })
  public Response getCalendar(
      @Parameter(description = "Filter events by capture agent")
      @QueryParam("agentid") String captureAgentId,
      @Parameter(description = "Filter events by series")
      @QueryParam("seriesid") String seriesId,
      @Parameter(
          description = "A cutoff date in UNIX milliseconds to limit the number of "
              + "events returned in the calendar."
      )
      @QueryParam("cutoff") String cutoff,
      @Context HttpServletRequest request
  ) {
    Date endDate = null;
    if (StringUtils.isNotBlank(cutoff)) {
      try {
        endDate = new Date(Long.parseLong(cutoff));
      } catch (NumberFormatException e) {
        return Response.status(Status.BAD_REQUEST).build();
      }
    }

    try {
      String lastModified = null;
      // If the etag matches the if-not-modified header,return a 304
      if (StringUtils.isNotBlank(captureAgentId)) {
        lastModified = service.getScheduleLastModified(captureAgentId);
        String ifNoneMatch = request.getHeader(HttpHeaders.IF_NONE_MATCH);
        if (StringUtils.isNotBlank(ifNoneMatch) && ifNoneMatch.equals(lastModified)) {
          return Response.notModified(lastModified).expires(null).build();
        }
      }

      String result = service.getCalendar(Optional.ofNullable(StringUtils.trimToNull(captureAgentId)),
              Optional.ofNullable(StringUtils.trimToNull(seriesId)), Optional.ofNullable(endDate));

      ResponseBuilder response = Response.ok(result).header(HttpHeaders.CONTENT_TYPE, "text/calendar; charset=UTF-8");
      if (StringUtils.isNotBlank(lastModified)) {
        response.header(HttpHeaders.ETAG, lastModified);
      }
      return response.build();
    } catch (Exception e) {
      logger.error("Unable to get calendar for capture agent '{}':", captureAgentId, e);
      throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  @GET
  @Produces("application/json")
  @Path("calendar.json")
  @Operation(
      summary = "Get events as JSON calendar",
      description = "Returns a calendar in JSON format for specified events."
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "304",
          description = "Events were not modified since last request"
      ),
      @ApiResponse(
          responseCode = "200",
          description = "Events were modified, new calendar is in the body"
      ),
      @ApiResponse(responseCode = "500", description = "An internal error occurred.")
  })
  public Response getCalendarJson(
      @Parameter(description = "Filter events by capture agent")
      @QueryParam("agentid") String captureAgentId,
      @Parameter(
          description = "A cutoff date in UNIX milliseconds to limit the number of "
              + "events returned in the calendar."
      )
      @QueryParam("cutoff") Long cutoff,
      @Parameter(
          description = "Return dates as UNIX timestamp in milliseconds instead of a date string."
      )
      @QueryParam("timestamp") Boolean timestamp,
      @Context HttpServletRequest request
  ) {
    try {
      var endDate = Optional.ofNullable(cutoff)
              .map(Date::new);
      var agent = Optional.ofNullable(captureAgentId)
              .map(String::trim)
              .filter(id -> !id.isEmpty());
      timestamp = !Objects.isNull(timestamp) && timestamp;

      String lastModified = null;
      // If the `etag` matches the if-not-modified header,return a 304
      if (agent.isPresent()) {
        lastModified = service.getScheduleLastModified(agent.get());
        String ifNoneMatch = request.getHeader(HttpHeaders.IF_NONE_MATCH);
        if (StringUtils.isNotBlank(ifNoneMatch) && ifNoneMatch.equals(lastModified)) {
          return Response.notModified(lastModified).expires(null).build();
        }
      }

      var result = new ArrayList<Map<String, Object>>();
      for (var event: service.search(agent, Optional.empty(), Optional.empty(), Optional.of(new Date()), endDate)) {
        var id = event.getIdentifier().toString();
        result.add(Map.of(
                "data", service.getTechnicalMetadata(id),
                "episode-dublincore", service.getDublinCore(id).toXmlString()
                ));
      }

      final ResponseBuilder response = Response.ok((timestamp ? gsonTimestamp : gson).toJson(result));
      if (StringUtils.isNotBlank(lastModified)) {
        response.header(HttpHeaders.ETAG, lastModified);
      }
      return response.build();
    } catch (Exception e) {
      throw new WebApplicationException(
              String.format("Unable to get calendar for capture agent %s", captureAgentId),
              e, Response.Status.INTERNAL_SERVER_ERROR);
    }
  }


  @GET
  @Produces(MediaType.TEXT_PLAIN)
  @Path("{id}/lastmodified")
  @Operation(
      summary = "Get the last modified hash of an agent's calendar",
      description = "Retrieves the last modified hash for specified agent"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "The last modified hash of agent is in the body of response"
      ),
      @ApiResponse(responseCode = "500", description = "An internal error occurred.")
  })
  public Response getLastModified(
      @Parameter(
          description = "ID of capture agent for which the last modified hash will be retrieved",
          required = true
      )
      @PathParam("id") String agentId
  ) {
    try {
      String lastModified = service.getScheduleLastModified(agentId);
      return Response.ok(lastModified).build();
    } catch (Exception e) {
      logger.error("Unable to retrieve agent last modified hash of agent id '{}': {}", agentId, getMessage(e));
      throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  @POST
  @Path("/removeOldScheduledRecordings")
  @Operation(
      summary = "Remove old scheduled events",
      description = "This will find and remove any scheduled events before the buffer time to keep performance in the "
          + "scheduler optimum."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Removed old scheduled recordings."),
      @ApiResponse(responseCode = "400", description = "Unable to parse buffer."),
      @ApiResponse(
          responseCode = "401",
          description = "You do not have permission to remove old schedulings. Maybe you need to authenticate."
      )
  })
  public Response removeOldScheduledRecordings(
      @Parameter(
          description = "The amount of seconds before now that a capture has to have stopped capturing. "
              + "It must be 0 or greater.",
          required = true,
          schema = @Schema(example = "604800")
      )
      @FormParam("buffer") long buffer
  ) throws UnauthorizedException {
    if (buffer < 0) {
      return Response.status(SC_BAD_REQUEST).build();
    }

    try {
      service.removeScheduledRecordingsBeforeBuffer(buffer);
    } catch (SchedulerException e) {
      logger.error("Error while trying to remove old scheduled recordings", e);
      throw new WebApplicationException(e);
    }
    return Response.ok().build();
  }


  /**
   * Creates new event based on parameters. All times and dates are in milliseconds.
   */
  @POST
  @Path("/")
  @Operation(
      summary = "Create an event",
      description = "Creates new event with specified parameters"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "201", description = "Event is successfully created"),
      @ApiResponse(
          responseCode = "409",
          description = "Unable to create event, conflicting events found (ConflictsFound) or event locked by a "
              + "transaction (TransactionLock)"
      ),
      @ApiResponse(
          responseCode = "401",
          description = "You do not have permission to create the event. Maybe you need to authenticate."
      ),
      @ApiResponse(responseCode = "400", description = "Missing or invalid information for this request"),
      @ApiResponse(responseCode = "500", description = "An internal error occurred.")
  })
  public Response addEvent(
      @Parameter(description = "The start date of the event in milliseconds from 1970-01-01T00:00:00Z", required = true)
      @FormParam("start") long startTime,
      @Parameter(description = "The end date of the event in milliseconds from 1970-01-01T00:00:00Z", required = true)
      @FormParam("end") long endTime,
      @Parameter(description = "The agent of the event", required = true)
      @FormParam("agent") String agentId,
      @Parameter(description = "Comma separated list of user ids (speakers/lecturers) for the event")
      @FormParam("users") String users,
      @Parameter(description = "The media package of the event", required = true)
      @FormParam("mediaPackage") String mediaPackageXml,
      @Parameter(
          description = "Workflow "
              + "configuration keys for the event. Each key will be prefixed by 'org.opencastproject.workflow"
              + ".config.' and added to the capture agent parameters."
      )
      @FormParam("wfproperties") String workflowProperties,
      @Parameter(description = "The capture agent properties for the event")
      @FormParam("agentparameters") String agentParameters,
      @Parameter(description = "The scheduling source of the event")
      @FormParam("source") String schedulingSource
  ) throws UnauthorizedException {
    if (endTime <= startTime || startTime < 0) {
      logger.debug("Cannot add event without proper start and end time");
      return RestUtil.R.badRequest("Cannot add event without proper start and end time");
    }

    if (StringUtils.isBlank(agentId)) {
      logger.debug("Cannot add event without agent identifier");
      return RestUtil.R.badRequest("Cannot add event without agent identifier");
    }

    if (StringUtils.isBlank(mediaPackageXml)) {
      logger.debug("Cannot add event without media package");
      return RestUtil.R.badRequest("Cannot add event without media package");
    }

    MediaPackage mediaPackage;
    try {
      mediaPackage = MediaPackageParser.getFromXml(mediaPackageXml);
    } catch (MediaPackageException e) {
      logger.debug("Could not parse media package", e);
      return RestUtil.R.badRequest("Could not parse media package");
    }

    String eventId = mediaPackage.getIdentifier().toString();

    Map<String, String> caProperties = new HashMap<>();
    if (StringUtils.isNotBlank(agentParameters)) {
      try {
        Properties prop = parseProperties(agentParameters);
        caProperties.putAll((Map) prop);
      } catch (Exception e) {
        logger.info("Could not parse capture agent properties: {}", agentParameters);
        return RestUtil.R.badRequest("Could not parse capture agent properties");
      }
    }

    Map<String, String> wfProperties = new HashMap<>();
    if (StringUtils.isNotBlank(workflowProperties)) {
      try {
        Properties prop = parseProperties(workflowProperties);
        wfProperties.putAll((Map) prop);
      } catch (IOException e) {
        logger.info("Could not parse workflow configuration properties: {}", workflowProperties);
        return RestUtil.R.badRequest("Could not parse workflow configuration properties");
      }
    }
    Set<String> userIds = new HashSet<>();
    String[] ids = StringUtils.split(users, ",");
    if (ids != null) {
      userIds.addAll(Arrays.asList(ids));
    }

    DateTime startDate = new DateTime(startTime).toDateTime(DateTimeZone.UTC);
    DateTime endDate = new DateTime(endTime).toDateTime(DateTimeZone.UTC);

    try {
      service.addEvent(startDate.toDate(), endDate.toDate(), agentId, userIds, mediaPackage, wfProperties, caProperties,
              Optional.ofNullable(schedulingSource));
      return Response.status(Status.CREATED)
              .header("Location", serverUrl + serviceUrl + '/' + eventId + "/mediapackage.xml").build();
    } catch (UnauthorizedException e) {
      throw e;
    } catch (SchedulerConflictException e) {
      return Response.status(Status.CONFLICT).entity(generateErrorResponse(e)).type(MediaType.APPLICATION_JSON).build();
    } catch (Exception e) {
      logger.error("Unable to create new event with id '{}'", eventId, e);
      return Response.serverError().build();
    }
  }

  /**
   * Creates new event based on parameters. All times and dates are in milliseconds.
   */
  @POST
  @Path("/multiple")
  @Operation(
      summary = "Create multiple events",
      description = "Creates new event with specified parameters"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "201", description = "Event is successfully created"),
      @ApiResponse(
          responseCode = "409",
          description = "Unable to create event, conflicting events found (ConflictsFound) or event locked by a "
              + "transaction (TransactionLock)"
      ),
      @ApiResponse(
          responseCode = "401",
          description = "You do not have permission to create the event. Maybe you need to authenticate."
      ),
      @ApiResponse(responseCode = "400", description = "Missing or invalid information for this request"),
      @ApiResponse(responseCode = "500", description = "An internal error occurred.")
  })
  public Response addMultipleEvents(
      @Parameter(description = "The recurrence rule for the events", required = true)
      @FormParam("rrule") String rruleString,
      @Parameter(description = "The start date of the event in milliseconds from 1970-01-01T00:00:00Z", required = true)
      @FormParam("start") long startTime,
      @Parameter(description = "The end date of the event in milliseconds from 1970-01-01T00:00:00Z", required = true)
      @FormParam("end") long endTime,
      @Parameter(description = "The duration of the events in milliseconds", required = true)
      @FormParam("duration") long duration,
      @Parameter(description = "The timezone of the events", required = true)
      @FormParam("tz") String tzString,
      @Parameter(description = "The agent of the event", required = true)
      @FormParam("agent") String agentId,
      @Parameter(description = "Comma separated list of user ids (speakers/lecturers) for the event")
      @FormParam("users") String users,
      @Parameter(
          description = "The template mediapackage for the events",
          required = true,
          schema = @Schema(type = "string")
      )
      @FormParam("templateMp") MediaPackage templateMp,
      @Parameter(
          description = "Workflow "
              + "configuration keys for the event. Each key will be prefixed by 'org.opencastproject.workflow"
              + ".config.' and added to the capture agent parameters."
      )
      @FormParam("wfproperties") String workflowProperties,
      @Parameter(description = "The capture agent properties for the event")
      @FormParam("agentparameters") String agentParameters,
      @Parameter(description = "The scheduling source of the event")
      @FormParam("source") String schedulingSource
  ) throws UnauthorizedException {
    if (endTime <= startTime || startTime < 0) {
      logger.debug("Cannot add event without proper start and end time");
      return RestUtil.R.badRequest("Cannot add event without proper start and end time");
    }

    RRule<ZonedDateTime> rrule;
    try {
      rrule = new RRule<>(rruleString);
    } catch (IllegalArgumentException e) {
      logger.debug("Could not parse recurrence rule");
      return RestUtil.R.badRequest("Could not parse recurrence rule");
    }

    if (duration < 1) {
      logger.debug("Cannot schedule events with durations less than 1");
      return RestUtil.R.badRequest("Cannot schedule events with durations less than 1");
    }

    if (StringUtils.isBlank(tzString)) {
      logger.debug("Cannot schedule events with blank timezone");
      return RestUtil.R.badRequest("Cannot schedule events with blank timezone");
    }
    TimeZone tz = TimeZone.getTimeZone(tzString);

    if (StringUtils.isBlank(agentId)) {
      logger.debug("Cannot add event without agent identifier");
      return RestUtil.R.badRequest("Cannot add event without agent identifier");
    }

    if (templateMp == null) {
      logger.debug("Cannot add event without a template media package");
      return RestUtil.R.badRequest("Cannot add event without a template media package");
    }
    // The template media package form parameter is converted by JAX-RS through
    // MediaPackageImpl.valueOf(String), which already validates the identifiers; repeat the
    // check here so the endpoint stays safe even if the conversion path ever changes.
    try {
      MediaPackageSupport.checkPathSafety(templateMp);
    } catch (IllegalArgumentException e) {
      logger.info("Cannot schedule events from a template media package with invalid identifiers");
      return RestUtil.R.badRequest("The template media package contains invalid identifiers");
    }

    Map<String, String> caProperties = new HashMap<>();
    if (StringUtils.isNotBlank(agentParameters)) {
      try {
        Properties prop = parseProperties(agentParameters);
        caProperties.putAll((Map) prop);
      } catch (Exception e) {
        logger.info("Could not parse capture agent properties: {}", agentParameters);
        return RestUtil.R.badRequest("Could not parse capture agent properties");
      }
    }

    Map<String, String> wfProperties = new HashMap<>();
    if (StringUtils.isNotBlank(workflowProperties)) {
      try {
        Properties prop = parseProperties(workflowProperties);
        wfProperties.putAll((Map) prop);
      } catch (IOException e) {
        logger.info("Could not parse workflow configuration properties: {}", workflowProperties);
        return RestUtil.R.badRequest("Could not parse workflow configuration properties");
      }
    }
    Set<String> userIds = new HashSet<>();
    String[] ids = StringUtils.split(users, ",");
    if (ids != null) {
      userIds.addAll(Arrays.asList(ids));
    }

    // ical4j expects start and end dates to be in TimeZone to be schedule to (not UTC)
    DateTime startDate = new DateTime(startTime).toDateTime(DateTimeZone.forTimeZone(tz));
    DateTime endDate = new DateTime(endTime).toDateTime(DateTimeZone.forTimeZone(tz));

    try {
      service.addMultipleEvents(rrule, startDate.toDate(), endDate.toDate(), duration, tz, agentId, userIds, templateMp,
              wfProperties, caProperties, Optional.ofNullable(schedulingSource));
      return Response.status(Status.CREATED).build();
    } catch (UnauthorizedException e) {
      throw e;
    } catch (SchedulerConflictException e) {
      return Response.status(Status.CONFLICT).entity(generateErrorResponse(e)).type(MediaType.APPLICATION_JSON).build();
    } catch (Exception e) {
      logger.error("Unable to create new events", e);
      return Response.serverError().build();
    }
  }

  @PUT
  @Path("{id}")
  @Operation(
      summary = "Update an event",
      description = "Updates specified event"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Event was successfully updated"),
      @ApiResponse(responseCode = "404", description = "Event with specified ID does not exist"),
      @ApiResponse(
          responseCode = "409",
          description = "Unable to update event, conflicting events found (ConflictsFound) or event locked by a "
              + "transaction (TransactionLock)"
      ),
      @ApiResponse(responseCode = "403", description = "Event with specified ID cannot be updated"),
      @ApiResponse(
          responseCode = "401",
          description = "You do not have permission to update the event. Maybe you need to authenticate."
      ),
      @ApiResponse(responseCode = "400", description = "Data is missing or invalid"),
      @ApiResponse(responseCode = "500", description = "An internal error occurred.")
  })
  public Response updateEvent(
      @Parameter(description = "ID of event to be updated", required = true)
      @PathParam("id") String eventID,
      @Parameter(description = "Updated start date for event")
      @FormParam("start") Long startTime,
      @Parameter(description = "Updated end date for event")
      @FormParam("end") Long endTime,
      @Parameter(description = "Updated agent for event")
      @FormParam("agent") String agentId,
      @Parameter(description = "Updated comma separated list of user ids (speakers/lecturers) for the event")
      @FormParam("users") String users,
      @Parameter(description = "Updated media package for event")
      @FormParam("mediaPackage") String mediaPackageXml,
      @Parameter(description = "Workflow configuration properties")
      @FormParam("wfproperties") String workflowProperties,
      @Parameter(description = "Updated Capture Agent properties")
      @FormParam("agentparameters") String agentParameters
  ) throws UnauthorizedException {
    if (startTime != null) {
      if (startTime < 0) {
        logger.debug("Cannot add event with negative start time ({} < 0)", startTime);
        return RestUtil.R.badRequest("Cannot add event with negative start time");
      }
      if (endTime != null && endTime <= startTime) {
        logger.debug("Cannot add event without proper end time ({} <= {})", startTime, endTime);
        return RestUtil.R.badRequest("Cannot add event without proper end time");
      }
    }

    MediaPackage mediaPackage = null;
    if (StringUtils.isNotBlank(mediaPackageXml)) {
      try {
        mediaPackage = MediaPackageParser.getFromXml(mediaPackageXml);
      } catch (Exception e) {
        logger.debug("Could not parse media packagey", e);
        return Response.status(Status.BAD_REQUEST).build();
      }
    }

    Map<String, String> caProperties = null;
    if (StringUtils.isNotBlank(agentParameters)) {
      try {
        Properties prop = parseProperties(agentParameters);
        caProperties = new HashMap<>();
        caProperties.putAll((Map) prop);
      } catch (Exception e) {
        logger.debug("Could not parse capture agent properties: {}", agentParameters, e);
        return Response.status(Status.BAD_REQUEST).build();
      }
    }

    Map<String, String> wfProperties = null;
    if (StringUtils.isNotBlank(workflowProperties)) {
      try {
        Properties prop = parseProperties(workflowProperties);
        wfProperties = new HashMap<>();
        wfProperties.putAll((Map) prop);
      } catch (IOException e) {
        logger.debug("Could not parse workflow configuration properties: {}", workflowProperties, e);
        return Response.status(Status.BAD_REQUEST).build();
      }
    }

    Set<String> userIds = null;
    String[] ids = StringUtils.split(StringUtils.trimToNull(users), ",");
    if (ids != null) {
      userIds = new HashSet<>(Arrays.asList(ids));
    }

    Date startDate = null;
    if (startTime != null) {
      startDate = new DateTime(startTime).toDateTime(DateTimeZone.UTC).toDate();
    }

    Date endDate = null;
    if (endTime != null) {
      endDate = new DateTime(endTime).toDateTime(DateTimeZone.UTC).toDate();
    }

    try {
      service.updateEvent(eventID, Optional.ofNullable(startDate), Optional.ofNullable(endDate),
              Optional.ofNullable(StringUtils.trimToNull(agentId)), Optional.ofNullable(userIds),
              Optional.ofNullable(mediaPackage), Optional.ofNullable(wfProperties), Optional.ofNullable(caProperties));
      return Response.ok().build();
    } catch (SchedulerConflictException e) {
      return Response.status(Status.CONFLICT).entity(generateErrorResponse(e)).type(MediaType.APPLICATION_JSON).build();
    } catch (SchedulerException e) {
      logger.warn("Error updating event with id '{}'", eventID, e);
      return Response.status(Status.FORBIDDEN).build();
    } catch (NotFoundException e) {
      logger.info("Event with id '{}' does not exist.", eventID);
      return Response.status(Status.NOT_FOUND).build();
    } catch (UnauthorizedException e) {
      throw e;
    } catch (Exception e) {
      logger.error("Unable to update event with id '{}'", eventID, e);
      return Response.serverError().build();
    }
  }

  @GET
  @Path("currentRecording/{agent}")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Get the current event of an agent as XML",
      description = "Get the current capture event as XML"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "current event is in the body of response"),
      @ApiResponse(responseCode = "204", description = "There is no current recording"),
      @ApiResponse(responseCode = "500", description = "An internal error occurred.")
  })
  public Response currentRecording(
      @Parameter(description = "The agent identifier", required = true)
      @PathParam("agent") String agentId
  ) throws UnauthorizedException {
    try {
      Optional<MediaPackage> current = service.getCurrentRecording(agentId);
      if (current.isEmpty()) {
        return Response.noContent().build();
      } else {
        return Response.ok(MediaPackageParser.getAsXml(current.get())).build();
      }
    } catch (UnauthorizedException e) {
      throw e;
    } catch (Exception e) {
      logger.error("Unable to get the current recording for agent '{}'", agentId, e);
      throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  @GET
  @Path("upcomingRecording/{agent}")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Get the upcoming event of an agent as XML",
      description = "Get the upcoming capture event as XML"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "upcoming event is in the body of response"),
      @ApiResponse(responseCode = "204", description = "There is no upcoming recording"),
      @ApiResponse(responseCode = "500", description = "An internal error occurred.")
  })
  public Response upcomingRecording(
      @Parameter(description = "The agent identifier", required = true)
      @PathParam("agent") String agentId
  ) throws UnauthorizedException {
    try {
      Optional<MediaPackage> upcoming = service.getUpcomingRecording(agentId);
      if (upcoming.isEmpty()) {
        return Response.noContent().build();
      } else {
        return Response.ok(MediaPackageParser.getAsXml(upcoming.get())).build();
      }
    } catch (UnauthorizedException e) {
      throw e;
    } catch (Exception e) {
      logger.error("Unable to get the upcoming recording for agent '{}'", agentId, e);
      throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  @GET
  @Path("eventCount")
  @Produces(MediaType.TEXT_PLAIN)
  @Operation(
      summary = "Get the number of scheduled events",
      description = "Get the number of scheduled events"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The event count"),
      @ApiResponse(responseCode = "500", description = "An internal error occurred.")
  })
  public Response eventCount() throws UnauthorizedException {
    try {
      return Response.ok("" + service.getEventCount()).build();
    } catch (UnauthorizedException e) {
      throw e;
    } catch (Exception e) {
      logger.error("Unable to get the event count", e);
      throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  @GET
  @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
  @Path("recordings.{type:xml|json}")
  @Operation(
      summary = "Search events",
      description = "Searches recordings and returns result as XML or JSON"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Search completed, results returned in body"),
      @ApiResponse(responseCode = "500", description = "An internal error occurred.")
  })
  public Response getEventsAsList(
      @Parameter(description = "The media type of the response [xml|json]", required = true)
      @PathParam("type") final String type,
      @Parameter(description = "Search by device")
      @QueryParam("agent") String device,
      @Parameter(description = "Search by when does event start")
      @QueryParam("startsfrom") Long startsFromTime,
      @Parameter(description = "Search by when does event start")
      @QueryParam("startsto") Long startsToTime,
      @Parameter(description = "Search by when does event finish")
      @QueryParam("endsfrom") Long endsFromTime,
      @Parameter(description = "Search by when does event finish")
      @QueryParam("endsto") Long endsToTime
  ) throws UnauthorizedException {
    Date startsfrom = null;
    Date startsTo = null;
    Date endsFrom = null;
    Date endsTo = null;
    if (startsFromTime != null) {
      startsfrom = new DateTime(startsFromTime).toDateTime(DateTimeZone.UTC).toDate();
    }
    if (startsToTime != null) {
      startsTo = new DateTime(startsToTime).toDateTime(DateTimeZone.UTC).toDate();
    }
    if (endsFromTime != null) {
      endsFrom = new DateTime(endsFromTime).toDateTime(DateTimeZone.UTC).toDate();
    }
    if (endsToTime != null) {
      endsTo = new DateTime(endsToTime).toDateTime(DateTimeZone.UTC).toDate();
    }

    try {
      List<MediaPackage> events = service.search(Optional.ofNullable(StringUtils.trimToNull(device)),
              Optional.ofNullable(startsfrom), Optional.ofNullable(startsTo), Optional.ofNullable(endsFrom),
              Optional.ofNullable(endsTo));
      if ("json".equalsIgnoreCase(type)) {
        return Response.ok(getEventListAsJsonString(events)).build();
      } else {
        return Response.ok(MediaPackageParser.getArrayAsXml(events)).build();
      }
    } catch (UnauthorizedException e) {
      throw e;
    } catch (Exception e) {
      logger.error("Unable to perform search: {}", getMessage(e));
      throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }
  }
  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("conflicts.json")
  @Operation(
      summary = "Find conflicting events as JSON",
      description = "Searches for conflicting recordings based on parameters"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "No conflicting events found"),
      @ApiResponse(responseCode = "200", description = "Found conflicting events, returned in body of response"),
      @ApiResponse(responseCode = "400", description = "Missing or invalid parameters"),
      @ApiResponse(responseCode = "401", description = "Not authorized to make this request"),
      @ApiResponse(responseCode = "500", description = "A detailed stack track of the internal issue.")
  })
  public Response getConflictingEventsJson(
      @Parameter(description = "Device identifier for which conflicts will be searched", required = true)
      @QueryParam("agent") String device,
      @Parameter(
          description = "Rule for recurrent conflicting, "
              + "specified as: \"FREQ=WEEKLY;BYDAY=day(s);BYHOUR=hour;BYMINUTE=minute\". FREQ is required. "
              + "BYDAY may include one or more (separated by commas) of the following: SU,MO,TU,WE,TH,FR,SA."
      )
      @QueryParam("rrule") String rrule,
      @Parameter(description = "Start time of conflicting period, in milliseconds", required = true)
      @QueryParam("start") Long startDate,
      @Parameter(description = "End time of conflicting period, in milliseconds", required = true)
      @QueryParam("end") Long endDate,
      @Parameter(
          description = "If recurrence rule is specified duration of each conflicting period, in milliseconds"
      )
      @QueryParam("duration") Long duration,
      @Parameter(description = "The timezone of the capture device")
      @QueryParam("timezone") String timezone
  ) throws UnauthorizedException {
    try {
      List<MediaPackage> events = getConflictingEvents(device, rrule, startDate, endDate, duration, timezone);
      if (!events.isEmpty()) {
        String eventsJsonString = getEventListAsJsonString(events);
        return Response.ok(eventsJsonString).build();
      } else {
        return Response.noContent().build();
      }
    } catch (IllegalArgumentException e) {
      return Response.status(Status.BAD_REQUEST).build();
    } catch (UnauthorizedException e) {
      throw e;
    } catch (Exception e) {
      logger.error("Unable to find conflicting events for {}, {}, {}, {}, {}:",
              device, rrule, startDate, endDate, duration, e);
      throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  @GET
  @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
  @Path("conflicts.{type:xml|json}")
  @Operation(
      summary = "Find conflicting events",
      description = "Searches for conflicting recordings based on parameters and returns result as XML or JSON"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "No conflicting events found"),
      @ApiResponse(responseCode = "200", description = "Found conflicting events, returned in body of response"),
      @ApiResponse(responseCode = "400", description = "Missing or invalid parameters"),
      @ApiResponse(responseCode = "401", description = "Not authorized to make this request"),
      @ApiResponse(responseCode = "500", description = "A detailed stack track of the internal issue.")
  })
  public Response getConflicts(
      @Parameter(description = "The media type of the response [xml|json]", required = true)
      @PathParam("type") final String type,
      @Parameter(description = "Device identifier for which conflicts will be searched", required = true)
      @QueryParam("agent") String device,
      @Parameter(
          description = "Rule for recurrent conflicting, "
              + "specified as: \"FREQ=WEEKLY;BYDAY=day(s);BYHOUR=hour;BYMINUTE=minute\". FREQ is required. "
              + "BYDAY may include one or more (separated by commas) of the following: SU,MO,TU,WE,TH,FR,SA."
      )
      @QueryParam("rrule") String rrule,
      @Parameter(description = "Start time of conflicting period, in milliseconds", required = true)
      @QueryParam("start") Long startDate,
      @Parameter(description = "End time of conflicting period, in milliseconds", required = true)
      @QueryParam("end") Long endDate,
      @Parameter(
          description = "If recurrence rule is specified duration of each conflicting period, in milliseconds"
      )
      @QueryParam("duration") Long duration,
      @Parameter(description = "The timezone of the capture device")
      @QueryParam("timezone") String timezone
  ) throws UnauthorizedException {
    // Pass dates in the TZ to be schedule to (not UTC)
    // If no timezone passed, use the local timezone of the system
    if (StringUtils.isBlank(timezone)) {
      timezone = DateTimeZone.getDefault().toString();
    }

    try {
      List<MediaPackage> events = getConflictingEvents(device, rrule, startDate, endDate, duration, timezone);
      if (!events.isEmpty()) {
        if ("json".equalsIgnoreCase(type)) {
          return Response.ok(getEventListAsJsonString(events)).build();
        } else {
          return Response.ok(MediaPackageParser.getArrayAsXml(events)).build();
        }
      } else {
        return Response.noContent().build();
      }
    } catch (IllegalArgumentException e) {
      return Response.status(Status.BAD_REQUEST).build();
    } catch (UnauthorizedException e) {
      throw e;
    } catch (Exception e) {
      logger.error("Unable to find conflicting events for {}, {}, {}, {}, {}",
              device, rrule, startDate, endDate, duration, e);
      throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  @PUT
  @Path("{id}/recordingStatus")
  @Operation(
      summary = "Set the state of a recording",
      description = "Set the status of a given recording, registering it if it is new"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "{id} set to {state}"),
      @ApiResponse(responseCode = "400", description = "{id} or state {state} is empty or the {state} is not known"),
      @ApiResponse(responseCode = "404", description = "Recording with {id} could not be found"),
      @ApiResponse(responseCode = "500", description = "An internal error occurred.")
  })
  public Response updateRecordingState(
      @Parameter(description = "The ID of a given recording", required = true)
      @PathParam("id") String id,
      @Parameter(
          description = "The state of the recording. Must be one of the following: unknown, capturing, "
              + "capture_finished, capture_error, manifest, manifest_error, manifest_finished, compressing, "
              + "compressing_error, uploading, upload_finished, upload_error.",
          required = true
      )
      @FormParam("state") String state
  ) throws NotFoundException {
    if (StringUtils.isEmpty(id) || StringUtils.isEmpty(state)) {
      return Response.serverError().status(Response.Status.BAD_REQUEST).build();
    }

    try {
      if (service.updateRecordingState(id, state)) {
        return Response.ok(id + " set to " + state).build();
      } else {
        return Response.status(Response.Status.BAD_REQUEST).build();
      }
    } catch (SchedulerException e) {
      logger.debug("Unable to set recording state of {}:", id, e);
      return Response.serverError().build();
    }
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("{id}/recordingStatus")
  @Operation(
      summary = "Get the state of a recording",
      description = "Return the state of a given recording"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returns the state of the recording with the correct id"),
      @ApiResponse(responseCode = "404", description = "The recording with the specified ID does not exist"),
      @ApiResponse(responseCode = "500", description = "An internal error occurred.")
  })
  public Response getRecordingState(
      @Parameter(description = "The ID of a given recording", required = true)
      @PathParam("id") String id
  ) throws NotFoundException {
    try {
      Recording rec = service.getRecordingState(id);
      JsonObject json = new JsonObject();
      json.addProperty("id", rec.getID());
      json.addProperty("state", rec.getState());
      json.addProperty("lastHeardFrom", rec.getLastCheckinTime());
      return RestUtil.R.ok(json);
    } catch (SchedulerException e) {
      logger.debug("Unable to get recording state of {}:", id, e);
      return Response.serverError().build();
    }
  }

  @DELETE
  @Path("{id}/recordingStatus")
  @Operation(
      summary = "Remove the state of a recording",
      description = "Remove record of a given recording"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "{id} removed"),
      @ApiResponse(responseCode = "400", description = "{id} is empty"),
      @ApiResponse(responseCode = "404", description = "Recording with {id} could not be found"),
      @ApiResponse(responseCode = "500", description = "An internal error occurred.")
  })
  public Response removeRecording(
      @Parameter(description = "The ID of a given recording", required = true)
      @PathParam("id") String id
  ) throws NotFoundException {
    if (StringUtils.isEmpty(id)) {
      return Response.serverError().status(Response.Status.BAD_REQUEST).build();
    }

    try {
      service.removeRecording(id);
      return Response.ok(id + " removed").build();
    } catch (SchedulerException e) {
      logger.debug("Unable to remove recording with id '{}':", id, e);
      return Response.serverError().build();
    }
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("recordingStatus")
  @Operation(
      summary = "Get the state of all recordings",
      description = "Return all registered recordings and their state"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returns all known recordings."),
      @ApiResponse(responseCode = "500", description = "An internal error occurred.")
  })
  public Response getAllRecordings() {
    try {
      JsonArray update = new JsonArray();
      for (Entry<String, Recording> e : service.getKnownRecordings().entrySet()) {
        JsonObject recording = new JsonObject();
        recording.addProperty("id", e.getValue().getID());
        recording.addProperty("state", e.getValue().getState());
        recording.addProperty("lastHeardFrom", e.getValue().getLastCheckinTime());
        update.add(recording);
      }
      return RestUtil.R.ok(update.toString());
    } catch (SchedulerException e) {
      logger.debug("Unable to get all recordings:", e);
      throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   *
   *
   *
   * Prolonging service
   *
   *
   *
   *
   */

  @GET
  @Path("capture/{agent}")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the current capture event of an agent",
      description = "Get the current capture event catalog as JSON"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "DublinCore of current capture event is in the body of response"
      ),
      @ApiResponse(responseCode = "404", description = "There is no ongoing recording"),
      @ApiResponse(responseCode = "503", description = "The agent is not ready to communicate"),
      @ApiResponse(responseCode = "500", description = "An internal error occurred.")
  })
  public Response currentCapture(
      @Parameter(description = "The agent identifier", required = true)
      @PathParam("agent") String agentId
  ) throws NotFoundException {
    if (service == null || agentService == null) {
      return Response.serverError().status(Response.Status.SERVICE_UNAVAILABLE)
          .entity("Scheduler service is unavailable, please wait...").build();
    }

    try {
      Optional<MediaPackage> current = service.getCurrentRecording(agentId);
      if (current.isEmpty()) {
        logger.info("No recording to stop found for agent '{}'!", agentId);
        throw new NotFoundException("No recording to stop found for agent: " + agentId);
      } else {
        DublinCoreCatalog catalog = DublinCoreUtil.loadEpisodeDublinCore(workspace, current.get()).get();
        return Response.ok(catalog.toJson()).build();
      }
    } catch (NotFoundException e) {
      throw e;
    } catch (Exception e) {
      logger.error("Unable to get the immediate recording for agent '{}'", agentId, e);
      throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  @GET
  @Path("capture/{agent}/upcoming")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the upcoming capture event of an agent",
      description = "Get the upcoming capture event catalog as JSON"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "DublinCore of the upcomfing capture event is in the body of response"
      ),
      @ApiResponse(responseCode = "404", description = "There is no upcoming recording"),
      @ApiResponse(responseCode = "503", description = "The agent is not ready to communicate"),
      @ApiResponse(responseCode = "500", description = "An internal error occurred.")
  })
  public Response upcomingCapture(
      @Parameter(description = "The agent identifier", required = true)
      @PathParam("agent") String agentId
  ) throws NotFoundException {
    if (service == null || agentService == null) {
      return Response.serverError().status(Response.Status.SERVICE_UNAVAILABLE)
          .entity("Scheduler service is unavailable, please wait...").build();
    }

    try {
      Optional<MediaPackage> upcoming = service.getUpcomingRecording(agentId);
      if (upcoming.isEmpty()) {
        logger.info("No recording to stop found for agent '{}'!", agentId);
        throw new NotFoundException("No recording to stop found for agent: " + agentId);
      } else {
        DublinCoreCatalog catalog = DublinCoreUtil.loadEpisodeDublinCore(workspace, upcoming.get()).get();
        return Response.ok(catalog.toJson()).build();
      }
    } catch (NotFoundException e) {
      throw e;
    } catch (Exception e) {
      logger.error("Unable to get the immediate recording for agent '{}'", agentId, e);
      throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  @POST
  @Path("capture/{agent}")
  @Operation(
      summary = "Start an immediate capture",
      description = "Create an immediate event"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "201", description = "Recording started"),
      @ApiResponse(responseCode = "404", description = "There is no such agent"),
      @ApiResponse(responseCode = "409", description = "The agent is already recording"),
      @ApiResponse(
          responseCode = "401",
          description = "You do not have permission "
              + "to start this immediate capture. Maybe you need to authenticate."
      ),
      @ApiResponse(responseCode = "503", description = "The agent is not ready to communicate"),
      @ApiResponse(responseCode = "500", description = "An internal error occurred.")
  })
  public Response startCapture(
      @Parameter(description = "The agent identifier", required = true)
      @PathParam("agent") String agentId,
      @Parameter(description = "The workflow definition id to use")
      @FormParam("workflowDefinitionId") String wfId
  ) throws NotFoundException, UnauthorizedException {
    if (service == null || agentService == null || prolongingService == null) {
      return Response.serverError().status(Response.Status.SERVICE_UNAVAILABLE)
          .entity("Scheduler service is unavailable, please wait...").build();
    }

    // Lookup the agent. If it doesn't exist, add a temporary registration
    boolean adHocRegistration = false;
    try {
      agentService.getAgent(agentId);
    } catch (NotFoundException e) {
      Properties adHocProperties = new Properties();
      adHocProperties.put(AGENT_REGISTRATION_TYPE, AGENT_REGISTRATION_TYPE_ADHOC);
      agentService.setAgentConfiguration(agentId, adHocProperties);
      agentService.setAgentState(agentId, AgentState.CAPTURING);
      adHocRegistration = true;
      logger.info("Temporarily registered agent '{}' for ad-hoc recording", agentId);
    }

    try {
      Date now = new Date();
      Date temporaryEndDate = DateTime.now().plus(prolongingService.getInitialTime()).toDate();
      try {
        List<MediaPackage> events = service.findConflictingEvents(agentId, now, temporaryEndDate);
        if (!events.isEmpty()) {
          logger.info("An already existing event is in a conflict with the the one to be created on the agent {}!",
                  agentId);
          return Response.status(Status.CONFLICT).build();
        }
      } catch (SchedulerException e) {
        logger.error("Unable to create immediate event on agent {}", agentId, e);
        throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
      }

      String workflowId = defaultWorkflowDefinitionId;
      if (StringUtils.isNotBlank(wfId)) {
        workflowId = wfId;
      }

      Map<String, String> caProperties = new HashMap<>();
      caProperties.put("org.opencastproject.workflow.definition", workflowId);
      caProperties.put("event.location", agentId);
      caProperties.put("event.title", "Capture now event");
      // caProperties.put("org.opencastproject.workflow.config.captionHold", "false");
      // caProperties.put("org.opencastproject.workflow.config.archiveOp", "true");
      // caProperties.put("org.opencastproject.workflow.config.trimHold", "false");

      // TODO default metadata? configurable?
      // A temporal with start and end period is needed! As well PROPERTY_SPATIAL is needed
      DublinCoreCatalog eventCatalog = DublinCores.mkOpencastEpisode().getCatalog();
      eventCatalog.set(PROPERTY_TITLE, "Capture now event");
      eventCatalog.set(PROPERTY_TEMPORAL,
              EncodingSchemeUtils.encodePeriod(new DCMIPeriod(now, temporaryEndDate), Precision.Second));
      eventCatalog.set(PROPERTY_SPATIAL, agentId);
      eventCatalog.set(PROPERTY_CREATED, EncodingSchemeUtils.encodeDate(new Date(), Precision.Minute));
      // eventCatalog.set(PROPERTY_CREATOR, "demo");
      // eventCatalog.set(PROPERTY_SUBJECT, "demo");
      // eventCatalog.set(PROPERTY_LANGUAGE, "demo");
      // eventCatalog.set(PROPERTY_CONTRIBUTOR, "demo");
      // eventCatalog.set(PROPERTY_DESCRIPTION, "demo");

      // TODO workflow properties
      Map<String, String> wfProperties = new HashMap<>();

      MediaPackage mediaPackage = null;
      try {
        mediaPackage = MediaPackageBuilderFactory.newInstance().newMediaPackageBuilder().createNew();
        mediaPackage = addCatalog(workspace, IOUtils.toInputStream(eventCatalog.toXmlString(), "UTF-8"),
                "dublincore.xml", MediaPackageElements.EPISODE, mediaPackage);

        prolongingService.schedule(agentId);
        service.addEvent(now, temporaryEndDate, agentId, Collections.<String> emptySet(), mediaPackage, wfProperties,
                caProperties, Optional.empty());
        return Response.status(Status.CREATED)
                .header("Location", serverUrl + serviceUrl + '/' + mediaPackage.getIdentifier().toString() + ".xml")
                .build();
      } catch (Exception e) {
        prolongingService.stop(agentId);
        if (e instanceof UnauthorizedException) {
          throw (UnauthorizedException) e;
        }
        logger.error("Unable to create immediate event on agent {}", agentId, e);
        throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
      } finally {
        if (mediaPackage != null) {
          for (MediaPackageElement elem : mediaPackage.getElements()) {
            if (MediaPackageElements.EPISODE.matches(elem.getFlavor())) {
              try {
                workspace.delete(elem.getURI());
              } catch (NotFoundException e) {
                logger.warn("Unable to find (and hence, delete), this mediapackage '{}' element '{}'",
                    mediaPackage.getIdentifier(), elem.getIdentifier());
              } catch (IOException e) {
                throw new RuntimeException(e);
              }
            }
          }
        }
      }
    } catch (Throwable t) {
      throw t;
    } finally {
      if (adHocRegistration) {
        agentService.removeAgent(agentId);
        logger.info("Removed temporary registration for agent '{}'", agentId);
      }
    }
  }

  @DELETE
  @Path("capture/{agent}")
  @Produces(MediaType.TEXT_PLAIN)
  @Operation(
      summary = "Stop an immediate capture",
      description = "Stops an immediate capture."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Recording stopped"),
      @ApiResponse(responseCode = "304", description = "The recording was already stopped"),
      @ApiResponse(responseCode = "404", description = "There is no such agent"),
      @ApiResponse(
          responseCode = "401",
          description = "You do not have permission "
              + "to stop this immediate capture. Maybe you need to authenticate."
      ),
      @ApiResponse(responseCode = "503", description = "The agent is not ready to communicate"),
      @ApiResponse(responseCode = "500", description = "An internal error occurred.")
  })
  public Response stopCapture(
      @Parameter(description = "The agent identifier", required = true)
      @PathParam("agent") String agentId
  ) throws NotFoundException, UnauthorizedException {
    if (service == null || agentService == null || prolongingService == null) {
      return Response.serverError().status(Response.Status.SERVICE_UNAVAILABLE)
          .entity("Scheduler service is unavailable, please wait...").build();
    }

    boolean isAdHoc = false;
    try {
      Agent agent = agentService.getAgent(agentId);
      String registrationType = (String) agent.getConfiguration().get(AGENT_REGISTRATION_TYPE);
      isAdHoc = AGENT_REGISTRATION_TYPE_ADHOC.equals(registrationType);
    } catch (NotFoundException e) {
      logger.debug("Temporarily registered agent '{}' for ad-hoc recording already removed", agentId);
    }

    try {
      String eventId;
      MediaPackage mp;
      DublinCoreCatalog eventCatalog;
      try {
        Optional<MediaPackage> current = service.getCurrentRecording(agentId);
        if (current.isEmpty()) {
          logger.info("No recording to stop found for agent '{}'!", agentId);
          return Response.notModified().build();
        } else {
          mp = current.get();
          eventCatalog = DublinCoreUtil.loadEpisodeDublinCore(workspace, mp).get();
          eventId = mp.getIdentifier().toString();
        }
      } catch (Exception e) {
        logger.error("Unable to get the immediate recording for agent '{}'", agentId, e);
        throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
      }

      try {
        DCMIPeriod period = EncodingSchemeUtils
                .decodeMandatoryPeriod(eventCatalog.getFirst(DublinCore.PROPERTY_TEMPORAL));
        eventCatalog.set(PROPERTY_TEMPORAL,
                EncodingSchemeUtils.encodePeriod(new DCMIPeriod(period.getStart(), new Date()), Precision.Second));

        mp = addCatalog(workspace, IOUtils.toInputStream(eventCatalog.toXmlString(), "UTF-8"), "dublincore.xml",
                MediaPackageElements.EPISODE, mp);

        service.updateEvent(eventId, Optional.empty(), Optional.empty(), Optional.empty(),
                Optional.empty(), Optional.of(mp), Optional.empty(),
                Optional.empty());
        prolongingService.stop(agentId);
        return Response.ok().build();
      } catch (UnauthorizedException e) {
        throw e;
      } catch (Exception e) {
        logger.error("Unable to update the temporal of event '{}'", eventId, e);
        throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
      }
    } catch (Throwable t) {
      throw t;
    } finally {
      if (isAdHoc) {
        agentService.removeAgent(agentId);
        logger.info("Removed temporary agent registration '{}'", agentId);
      }
    }
  }

  @PUT
  @Path("capture/{agent}/prolong")
  @Produces(MediaType.TEXT_PLAIN)
  @Operation(
      summary = "Prolong an immediate capture",
      description = "Prolong an immediate capture."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Recording prolonged"),
      @ApiResponse(responseCode = "404", description = "No recording found for prolonging"),
      @ApiResponse(
          responseCode = "401",
          description = "You do not have permission "
              + "to prolong this immediate capture. Maybe you need to authenticate."
      ),
      @ApiResponse(responseCode = "503", description = "The agent is not ready to communicate"),
      @ApiResponse(responseCode = "500", description = "An internal error occurred.")
  })
  public Response prolongCapture(
      @Parameter(description = "The agent identifier", required = true)
      @PathParam("agent") String agentId
  ) throws NotFoundException, UnauthorizedException {
    if (service == null || agentService == null || prolongingService == null) {
      return Response.serverError().status(Response.Status.SERVICE_UNAVAILABLE)
          .entity("Scheduler service is unavailable, please wait...").build();
    }
    try {
      MediaPackage event = prolongingService.getCurrentRecording(agentId);
      DublinCoreCatalog dc = DublinCoreUtil.loadEpisodeDublinCore(workspace, event).get();
      prolongingService.prolongEvent(event, dc, agentId);
      return Response.ok().build();
    } catch (NotFoundException | UnauthorizedException e) {
      throw e;
    } catch (Exception e) {
      logger.error("Unable to prolong the immediate recording for agent '{}'", agentId, e);
      throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  private List<MediaPackage> getConflictingEvents(String device, String rrule,
          Long startDate, Long endDate, Long duration, String timezone)
                  throws IllegalArgumentException, UnauthorizedException, SchedulerException {

    List<MediaPackage> events = null;

    if (StringUtils.isBlank(device) || startDate == null || endDate == null) {
      logger.info("Either agent, start date or end date were not specified");
      throw new IllegalArgumentException();
    }

    RRule<ZonedDateTime> rule = null;
    if (StringUtils.isNotBlank(rrule)) {
      if (duration == null || StringUtils.isBlank(timezone)) {
        logger.info("Either duration or timezone were not specified");
        throw new IllegalArgumentException();
      }

      try {
        rule = new RRule<>(rrule);
        rule.validate();
      } catch (Exception e) {
        logger.info("Unable to parse rrule {}: {}", rrule, getMessage(e));
        throw new IllegalArgumentException();
      }

      if (!Arrays.asList(TimeZone.getAvailableIDs()).contains(timezone)) {
        logger.info("Unable to parse timezone: {}", timezone);
        throw new IllegalArgumentException();
      }
    }

    Date start = new DateTime(startDate).toDateTime(DateTimeZone.UTC).toDate();

    Date end = new DateTime(endDate).toDateTime(DateTimeZone.UTC).toDate();

    if (StringUtils.isNotBlank(rrule)) {
      events = service.findConflictingEvents(device, rule, start, end, duration, TimeZone.getTimeZone(timezone));
    } else {
      events = service.findConflictingEvents(device, start, end);
    }
    return events;
  }

  private MediaPackage addCatalog(Workspace workspace, InputStream in, String fileName,
          MediaPackageElementFlavor flavor, MediaPackage mediaPackage) throws IOException {
    Catalog[] catalogs = mediaPackage.getCatalogs(flavor);
    Catalog c = null;
    if (catalogs.length == 1) {
      c = catalogs[0];
    }

    // If catalog found, create a new one
    if (c == null) {
      c = (Catalog) MediaPackageElementBuilderFactory.newInstance().newElementBuilder()
              .newElement(MediaPackageElement.Type.Catalog, flavor);
      c.generateIdentifier();
      logger.info("Adding catalog with flavor {} to mediapackage {}", flavor, mediaPackage);
      mediaPackage.add(c);
    }

    // Update comments catalog
    try {
      URI catalogUrl = workspace.put(mediaPackage.getIdentifier().toString(), c.getIdentifier(), fileName, in);
      c.setURI(catalogUrl);
      // setting the URI to a new source so the checksum will most like be invalid
      c.setChecksum(null);
    } finally {
      IOUtils.closeQuietly(in);
    }
    return mediaPackage;
  }

  private String serializeProperties(Map<String, String> properties) {
    StringBuilder wfPropertiesString = new StringBuilder();
    for (Map.Entry<String, String> entry : properties.entrySet()) {
      wfPropertiesString.append(entry.getKey() + "=" + entry.getValue() + "\n");
    }
    return wfPropertiesString.toString();
  }

  /**
   * Parses Properties represented as String.
   *
   * @param serializedProperties
   *          properties to be parsed.
   * @return parsed properties
   * @throws IOException
   *           if parsing fails
   */
  private Properties parseProperties(String serializedProperties) throws IOException {
    Properties caProperties = new Properties();
    logger.debug("properties: {}", serializedProperties);
    caProperties.load(new StringReader(serializedProperties));
    return caProperties;
  }

  /**
   * Serializes mediapackage schedule metadata into JSON array string.
   *
   * @return serialized array as json array string
   * @throws SchedulerException
   *           if parsing list into JSON format fails
   */
  public String getEventListAsJsonString(List<MediaPackage> mpList) throws SchedulerException {
    JsonObject jsonObj = new JsonObject();
    JsonArray jsonArray = new JsonArray();
    for (MediaPackage mp: mpList) {
      try {
        JsonObject mpJson = GsonUtil.gson().fromJson(MediaPackageParser.getAsJSON(mp), JsonObject.class);
        jsonArray.add(mpJson.getAsJsonObject("mediapackage"));
      } catch (JsonParseException e) {
        logger.warn("Unexpected JSON parse exception for getAsJSON on mp {}", mp.getIdentifier().toString(), e);
        throw new SchedulerException(e);
      }
    }
    jsonObj.addProperty("totalCount", String.valueOf(mpList.size()));
    jsonObj.add("events", jsonArray);
    return jsonObj.toString();
  }
}
