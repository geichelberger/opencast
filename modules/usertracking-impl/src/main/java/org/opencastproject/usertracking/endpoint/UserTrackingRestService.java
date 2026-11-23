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

package org.opencastproject.usertracking.endpoint;


import org.opencastproject.rest.RestConstants;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.systems.OpencastConstants;
import org.opencastproject.usertracking.api.UserSession;
import org.opencastproject.usertracking.api.UserTrackingException;
import org.opencastproject.usertracking.api.UserTrackingService;
import org.opencastproject.usertracking.impl.UserActionImpl;
import org.opencastproject.usertracking.impl.UserActionListImpl;
import org.opencastproject.usertracking.impl.UserSessionImpl;
import org.opencastproject.util.NotFoundException;
import org.opencastproject.util.UrlSupport;

import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * REST Endpoint for User Tracking Service
 */
@Path("/usertracking")
@Tag(
    name = "User Tracking Service",
    description = "This service is used for tracking user interaction creates, edits and retrieves user actions and "
        + "viewing statistics."
)
@Component(
    immediate = true,
    service = UserTrackingRestService.class,
    property = {
        "service.description=User Tracking REST Endpoint",
        "opencast.service.type=org.opencastproject.usertracking",
        "opencast.service.path=/usertracking"
    }
)
@JaxrsResource
public class UserTrackingRestService {

  private static final Logger logger = LoggerFactory.getLogger(UserTrackingRestService.class);

  private UserTrackingService usertrackingService;

  protected SecurityService securityService;

  protected String serverUrl = UrlSupport.DEFAULT_BASE_URL;

  protected String serviceUrl = "/usertracking"; // set this to the default value initially

  /**
   * Method to set the service this REST endpoint uses
   *
   * @param service
   */
  @Reference
  public void setService(UserTrackingService service) {
    this.usertrackingService = service;
  }

  /**
   * Sets the security service
   *
   * @param securityService
   *          the securityService to set
   */
  @Reference
  public void setSecurityService(SecurityService securityService) {
    this.securityService = securityService;
  }

  /**
   * The method that is called, when the service is activated
   *
   * @param cc
   *          The ComponentContext of this service
   */
  @Activate
  public void activate(ComponentContext cc) {
    // Get the configured server URL
    if (cc == null) {
      serverUrl = UrlSupport.DEFAULT_BASE_URL;
    } else {
      String ccServerUrl = cc.getBundleContext().getProperty(OpencastConstants.SERVER_URL_PROPERTY);
      logger.info("configured server url is {}", ccServerUrl);
      if (ccServerUrl == null) {
        serverUrl = UrlSupport.DEFAULT_BASE_URL;
      } else {
        serverUrl = ccServerUrl;
      }
      serviceUrl = (String) cc.getProperties().get(RestConstants.SERVICE_PATH_PROPERTY);
    }
  }

  /**
   * @return XML with all footprints
   */
  @GET
  @Produces(MediaType.TEXT_XML)
  @Path("/actions.xml")
  @Operation(
      summary = "List user actions as XML",
      description = "Get user actions by type and day"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the user actions"),
      @ApiResponse(responseCode = "400", description = "The limit or the offset is negative.")
  })
  public UserActionListImpl getUserActionsAsXml(
      @Parameter(description = "The episode identifier. Together with the type, restricts the actions to this episode")
      @QueryParam("id") String id,
      @Parameter(description = "The type of the user action")
      @QueryParam("type") String type,
      @Parameter(description = "The day of creation (format: YYYYMMDD)")
      @QueryParam("day") String day,
      @Parameter(description = "The maximum number of items to return per page")
      @QueryParam("limit") int limit,
      @Parameter(description = "The index of the first item to return.")
      @QueryParam("offset") int offset
  ) {

    // Are the values of offset and limit valid?
    if (offset < 0 || limit < 0) {
      throw new WebApplicationException(Status.BAD_REQUEST);
    }

    // Set default value of limit (max result value)
    if (limit == 0) {
      limit = 10;
    }
    try {
      if (!StringUtils.isEmpty(id) && !StringUtils.isEmpty(type)) {
        return (UserActionListImpl) usertrackingService.getUserActionsByTypeAndMediapackageId(type, id, offset, limit);
      } else if (!StringUtils.isEmpty(type) && !StringUtils.isEmpty(day)) {
        return (UserActionListImpl) usertrackingService.getUserActionsByTypeAndDay(type, day, offset, limit);
      } else if (!StringUtils.isEmpty(type)) {
        return (UserActionListImpl) usertrackingService.getUserActionsByType(type, offset, limit);
      } else if (!StringUtils.isEmpty(day)) {
        return (UserActionListImpl) usertrackingService.getUserActionsByDay(day, offset, limit);
      } else {
        return (UserActionListImpl) usertrackingService.getUserActions(offset, limit);
      }
    } catch (UserTrackingException e) {
      throw new WebApplicationException(e);
    }
  }

  /**
   * @return JSON with all footprints
   */
  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("/actions.json")
  @Operation(
      summary = "List user actions as JSON",
      description = "Get user actions by type and day"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "A JSON representation of the user actions"),
      @ApiResponse(responseCode = "400", description = "The limit or the offset is negative.")
  })
  public UserActionListImpl getUserActionsAsJson(
      @Parameter(description = "The episode identifier. Together with the type, restricts the actions to this episode")
      @QueryParam("id") String id,
      @Parameter(description = "The type of the user action")
      @QueryParam("type") String type,
      @Parameter(description = "The day of creation (format: YYYYMMDD)")
      @QueryParam("day") String day,
      @Parameter(description = "The maximum number of items to return per page")
      @QueryParam("limit") int limit,
      @Parameter(description = "The index of the first item to return.")
      @QueryParam("offset") int offset
  ) {
    return getUserActionsAsXml(id, type, day, limit, offset); // same logic, different @Produces annotation
  }

  @GET
  @Produces(MediaType.TEXT_XML)
  @Path("/stats.xml")
  @Operation(
      summary = "Get the statistics of an episode as XML",
      description = "Get the statistics for an episode"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the episode's statistics")
  })
  public StatsImpl statsAsXml(
      @Parameter(
          description = "The ID of the single episode to return the statistics for, if it exists"
      )
      @QueryParam("id") String mediapackageId
  ) {
    StatsImpl s = new StatsImpl();
    s.setMediapackageId(mediapackageId);
    try {
      s.setViews(usertrackingService.getViews(mediapackageId));
    } catch (UserTrackingException e) {
      throw new WebApplicationException(e);
    }
    return s;
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("/stats.json")
  @Operation(
      summary = "Get the statistics of an episode as JSON",
      description = "Get the statistics for an episode"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "A JSON representation of the episode's statistics")
  })
  public StatsImpl statsAsJson(
      @Parameter(
          description = "The ID of the single episode to return the statistics for, if it exists"
      )
      @QueryParam("id") String mediapackageId
  ) {
    return statsAsXml(mediapackageId); // same logic, different @Produces annotation
  }

  @GET
  @Produces(MediaType.TEXT_XML)
  @Path("/report.xml")
  @Operation(
      summary = "Get a report as XML",
      description = "Get a report for a time range"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the report"),
      @ApiResponse(
          responseCode = "400",
          description = "The limit or the offset is negative, or the from or to date cannot be parsed."
      )
  })
  public ReportImpl reportAsXml(
      @Parameter(description = "The beginning of the time range")
      @QueryParam("from") String from,
      @Parameter(description = "The end of the time range")
      @QueryParam("to") String to,
      @Parameter(description = "The index of the first item to return.")
      @QueryParam("offset") int offset,
      @Parameter(description = "The maximum number of items to return per page")
      @QueryParam("limit") int limit
  ) {

    // Are the values of offset and limit valid?
    if (offset < 0 || limit < 0) {
      throw new WebApplicationException(Status.BAD_REQUEST);
    }

    // Set default value of limit (max result value)
    if (limit == 0) {
      limit = 10;
    }

    try {
      if (from == null && to == null) {
        return (ReportImpl) usertrackingService.getReport(offset, limit);
      } else {
        return (ReportImpl) usertrackingService.getReport(from, to, offset, limit);
      }
    } catch (UserTrackingException e) {
      throw new WebApplicationException(e);
    } catch (ParseException e) {
      throw new WebApplicationException(Status.BAD_REQUEST);
    }
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("/report.json")
  @Operation(
      summary = "Get a report as JSON",
      description = "Get a report for a time range"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "A JSON representation of the report"),
      @ApiResponse(
          responseCode = "400",
          description = "The limit or the offset is negative, or the from or to date cannot be parsed."
      )
  })
  public ReportImpl reportAsJson(
      @Parameter(description = "The beginning of the time range")
      @QueryParam("from") String from,
      @Parameter(description = "The end of the time range")
      @QueryParam("to") String to,
      @Parameter(description = "The index of the first item to return.")
      @QueryParam("offset") int offset,
      @Parameter(description = "The maximum number of items to return per page")
      @QueryParam("limit") int limit
  ) {
    return reportAsXml(from, to, offset, limit); // same logic, different @Produces annotation
  }

  @PUT
  @Path("")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Record a user action",
      description = "Record a user action"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "201", description = "An XML representation of the user action"),
      @ApiResponse(responseCode = "400", description = "The time range is missing or is not an integer")
  })
  public Response addFootprint(
      @Parameter(description = "The episode identifier", required = true)
      @FormParam("id") String mediapackageId,
      @Parameter(description = "The beginning of the time range", required = true)
      @FormParam("in") String inString,
      @Parameter(description = "The end of the time range")
      @FormParam("out") String outString,
      @Parameter(
          description = "The type of the user action. FOOTPRINT records a footprint, any other type a tracking event",
          required = true
      )
      @FormParam("type") String type,
      @Parameter(description = "Whether the player is currently playing")
      @FormParam("playing") String isPlaying,
      @Context HttpServletRequest request
  ) {

    String sessionId = request.getSession().getId();
    String userId = securityService.getUser().getUsername();

    // Parse the in and out strings, which might be empty (hence, we can't let jax-rs handle them properly)
    if (StringUtils.isEmpty(inString)) {
      throw new WebApplicationException(Response.status(Status.BAD_REQUEST).entity("in must be a non null integer")
              .build());
    }
    Integer in = null;
    try {
      in = Integer.parseInt(StringUtils.trim(inString));
    } catch (NumberFormatException e) {
      throw new WebApplicationException(e,
          Response.status(Status.BAD_REQUEST).entity("in must be a non null integer").build());
    }

    Integer out = null;
    if (StringUtils.isEmpty(outString)) {
      out = in;
    } else {
      try {
        out = Integer.parseInt(StringUtils.trim(outString));
      } catch (NumberFormatException e) {
        throw new WebApplicationException(e,
            Response.status(Status.BAD_REQUEST).entity("out must be a non null integer").build());
      }
    }

    //MH-8616 the connection might be via a proxy, which TransparentProxyFilter has already accounted for
    String clientIP = request.getRemoteAddr();
    logger.debug("Got client ip: {}", clientIP);

    UserSession s = new UserSessionImpl();
    s.setSessionId(sessionId);
    s.setUserIp(clientIP);
    s.setUserId(userId);
    //Column length is currently 255, let's limit it to that.
    String userAgent = StringUtils.trimToNull(request.getHeader("User-Agent"));
    if (userAgent != null && userAgent.length() > 255) {
      s.setUserAgent(userAgent.substring(0, 255));
    } else {
      s.setUserAgent(userAgent);
    }

    UserActionImpl a = new UserActionImpl();
    a.setMediapackageId(mediapackageId);
    a.setSession(s);
    a.setInpoint(in);
    a.setOutpoint(out);
    a.setType(type);
    a.setIsPlaying(Boolean.valueOf(isPlaying));

    try {
      if ("FOOTPRINT".equals(type)) {
        a = (UserActionImpl) usertrackingService.addUserFootprint(a, s);
      } else {
        a = (UserActionImpl) usertrackingService.addUserTrackingEvent(a, s);
      }
    } catch (UserTrackingException e) {
      throw new WebApplicationException(e);
    }

    URI uri;
    try {
      uri = new URI(UrlSupport.concat(new String[] { serverUrl, serviceUrl, "action", a.getId().toString(), ".xml" }));
    } catch (URISyntaxException e) {
      throw new WebApplicationException(e);
    }
    return Response.created(uri).entity(a).build();
  }

  @GET
  @Produces(MediaType.TEXT_XML)
  @Path("/action/{id}.xml")
  @Operation(
      summary = "Get a user action as XML",
      description = "Get a user action"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the user action")
  })
  public UserActionImpl getActionAsXml(
      @Parameter(description = "The user action identifier", required = true)
      @PathParam("id") String actionId
  ) {
    Long id = null;
    try {
      id = Long.parseLong(actionId);
    } catch (NumberFormatException e) {
      throw new WebApplicationException(e);
    }
    try {
      return (UserActionImpl) usertrackingService.getUserAction(id);
    } catch (UserTrackingException e) {
      throw new WebApplicationException(e);
    } catch (NotFoundException e) {
      return null;
    }
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("/action/{id}.json")
  @Operation(
      summary = "Get a user action as JSON",
      description = "Get a user action"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "A JSON representation of the user action")
  })
  public UserActionImpl getActionAsJson(
      @Parameter(description = "The user action identifier", required = true)
      @PathParam("id") String actionId
  ) {
    return getActionAsXml(actionId);
  }

  @GET
  @Produces(MediaType.TEXT_XML)
  @Path("/footprint.xml")
  @Operation(
      summary = "Get the footprints of an episode as XML",
      description = "Gets the 'footprint' action for an episode"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the footprints"),
      @ApiResponse(responseCode = "400", description = "The media package id is missing.")
  })
  public FootprintsListImpl getFootprintAsXml(
      @Parameter(description = "The episode identifier", required = true)
      @QueryParam("id") String mediapackageId
  ) {
    String userId = securityService.getUser().getUsername();

    // Is the mediapackageId passed
    if (mediapackageId == null) {
      throw new WebApplicationException(Status.BAD_REQUEST);
    }

    try {
      return (FootprintsListImpl) usertrackingService.getFootprints(mediapackageId, userId);
    } catch (UserTrackingException e) {
      throw new WebApplicationException(e);
    }
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("/footprint.json")
  @Operation(
      summary = "Get the footprints of an episode as JSON",
      description = "Gets the 'footprint' action for an episode"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "A JSON representation of the footprints"),
      @ApiResponse(responseCode = "400", description = "The media package id is missing.")
  })
  public FootprintsListImpl getFootprintAsJson(
      @Parameter(description = "The episode identifier", required = true)
      @QueryParam("id") String mediapackageId
  ) {
    return getFootprintAsXml(mediapackageId); // this is the same logic... it's just annotated differently
  }

  @GET
  @Produces(MediaType.TEXT_PLAIN)
  @Path("/detailenabled")
  @Operation(
      summary = "Check whether detailed user tracking is enabled",
      description = "Returns whether detailed user information is gathered. Turning detailed user tracking off "
          + "does not disable the gathering of footprints."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "true if detailed user tracking is enabled, false otherwise.")
  })
  public Response getUserTrackingEnabled() {
    return Response.ok(usertrackingService.getUserTrackingEnabled()).build();
  }
}
