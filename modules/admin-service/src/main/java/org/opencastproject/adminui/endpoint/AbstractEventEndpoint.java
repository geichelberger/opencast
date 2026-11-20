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

package org.opencastproject.adminui.endpoint;

import static java.lang.String.format;
import static javax.servlet.http.HttpServletResponse.SC_BAD_REQUEST;
import static javax.servlet.http.HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
import static javax.servlet.http.HttpServletResponse.SC_SERVICE_UNAVAILABLE;
import static javax.ws.rs.core.Response.Status.NOT_FOUND;
import static org.apache.commons.lang3.StringUtils.trimToNull;
import static org.opencastproject.adminui.endpoint.EndpointUtil.fromJettison;
import static org.opencastproject.adminui.endpoint.EndpointUtil.transformAccessControList;
import static org.opencastproject.index.service.impl.util.EventUtils.internalChannelFilter;
import static org.opencastproject.index.service.util.JSONUtils.arrayToJsonArray;
import static org.opencastproject.index.service.util.JSONUtils.collectionToJsonArray;
import static org.opencastproject.index.service.util.JSONUtils.mapToJsonObject;
import static org.opencastproject.index.service.util.JSONUtils.safeString;
import static org.opencastproject.index.service.util.RestUtils.conflictJson;
import static org.opencastproject.index.service.util.RestUtils.notFound;
import static org.opencastproject.index.service.util.RestUtils.notFoundJson;
import static org.opencastproject.index.service.util.RestUtils.okJson;
import static org.opencastproject.index.service.util.RestUtils.okJsonList;
import static org.opencastproject.index.service.util.RestUtils.serverErrorJson;
import static org.opencastproject.util.DateTimeSupport.toUTC;
import static org.opencastproject.util.RestUtil.R.badRequest;
import static org.opencastproject.util.RestUtil.R.conflict;
import static org.opencastproject.util.RestUtil.R.forbidden;
import static org.opencastproject.util.RestUtil.R.noContent;
import static org.opencastproject.util.RestUtil.R.notFound;
import static org.opencastproject.util.RestUtil.R.ok;
import static org.opencastproject.util.RestUtil.R.serverError;

import org.opencastproject.adminui.exception.JobEndpointException;
import org.opencastproject.adminui.impl.AdminUIConfiguration;
import org.opencastproject.adminui.tobira.TobiraException;
import org.opencastproject.adminui.tobira.TobiraService;
import org.opencastproject.adminui.util.BulkUpdateUtil;
import org.opencastproject.assetmanager.api.AssetManager;
import org.opencastproject.authorization.xacml.manager.api.AclService;
import org.opencastproject.authorization.xacml.manager.api.ManagedAcl;
import org.opencastproject.authorization.xacml.manager.util.AccessInformationUtil;
import org.opencastproject.capture.CaptureParameters;
import org.opencastproject.capture.admin.api.Agent;
import org.opencastproject.capture.admin.api.CaptureAgentStateService;
import org.opencastproject.event.comment.EventComment;
import org.opencastproject.event.comment.EventCommentException;
import org.opencastproject.event.comment.EventCommentReply;
import org.opencastproject.event.comment.EventCommentService;
import org.opencastproject.index.service.api.IndexService;
import org.opencastproject.index.service.api.IndexService.Source;
import org.opencastproject.index.service.exception.IndexServiceException;
import org.opencastproject.index.service.exception.UnsupportedAssetException;
import org.opencastproject.index.service.impl.util.EventUtils;
import org.opencastproject.index.service.util.JSONUtils;
import org.opencastproject.index.service.util.RestUtils;
import org.opencastproject.list.api.DefaultResourceListQuery;
import org.opencastproject.list.api.ListProviderException;
import org.opencastproject.list.api.ListProvidersService;
import org.opencastproject.list.api.ResourceListQuery;
import org.opencastproject.list.common.provider.EventsListProvider;
import org.opencastproject.list.common.provider.EventsListProvider.Comments;
import org.opencastproject.list.common.provider.EventsListProvider.IsPublished;
import org.opencastproject.list.common.query.EventListQuery;
import org.opencastproject.list.common.query.SeriesListQuery;
import org.opencastproject.mediapackage.Attachment;
import org.opencastproject.mediapackage.AudioStream;
import org.opencastproject.mediapackage.Catalog;
import org.opencastproject.mediapackage.MediaPackage;
import org.opencastproject.mediapackage.MediaPackageElement;
import org.opencastproject.mediapackage.MediaPackageException;
import org.opencastproject.mediapackage.Publication;
import org.opencastproject.mediapackage.Track;
import org.opencastproject.mediapackage.VideoStream;
import org.opencastproject.mediapackage.track.AudioStreamImpl;
import org.opencastproject.mediapackage.track.SubtitleStreamImpl;
import org.opencastproject.mediapackage.track.VideoStreamImpl;
import org.opencastproject.metadata.dublincore.DublinCore;
import org.opencastproject.metadata.dublincore.DublinCoreMetadataCollection;
import org.opencastproject.metadata.dublincore.EventCatalogUIAdapter;
import org.opencastproject.metadata.dublincore.MetadataField;
import org.opencastproject.metadata.dublincore.MetadataJson;
import org.opencastproject.metadata.dublincore.MetadataList;
import org.opencastproject.metadata.dublincore.MetadataList.Locked;
import org.opencastproject.opensearch.api.SearchIndexException;
import org.opencastproject.opensearch.api.SearchResult;
import org.opencastproject.opensearch.api.SearchResultItem;
import org.opencastproject.opensearch.index.OpenSearchIndex;
import org.opencastproject.opensearch.index.objects.event.Event;
import org.opencastproject.opensearch.index.objects.event.EventIndexSchema;
import org.opencastproject.opensearch.index.objects.event.EventSearchQuery;
import org.opencastproject.rest.BulkOperationResult;
import org.opencastproject.rest.RestConstants;
import org.opencastproject.scheduler.api.Recording;
import org.opencastproject.scheduler.api.SchedulerException;
import org.opencastproject.scheduler.api.SchedulerService;
import org.opencastproject.scheduler.api.TechnicalMetadata;
import org.opencastproject.scheduler.api.Util;
import org.opencastproject.security.api.AccessControlList;
import org.opencastproject.security.api.AccessControlParser;
import org.opencastproject.security.api.AclScope;
import org.opencastproject.security.api.AuthorizationService;
import org.opencastproject.security.api.Organization;
import org.opencastproject.security.api.Permissions;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.security.api.UnauthorizedException;
import org.opencastproject.security.api.User;
import org.opencastproject.security.api.UserDirectoryService;
import org.opencastproject.security.urlsigning.exception.UrlSigningException;
import org.opencastproject.security.urlsigning.service.UrlSigningService;
import org.opencastproject.security.util.SecurityUtil;
import org.opencastproject.systems.OpencastConstants;
import org.opencastproject.util.DateTimeSupport;
import org.opencastproject.util.GsonUtil;
import org.opencastproject.util.NotFoundException;
import org.opencastproject.util.RestUtil;
import org.opencastproject.util.UrlSupport;
import org.opencastproject.util.data.Tuple;
import org.opencastproject.util.data.Tuple3;
import org.opencastproject.util.requests.SortCriterion;
import org.opencastproject.workflow.api.RetryStrategy;
import org.opencastproject.workflow.api.WorkflowDatabaseException;
import org.opencastproject.workflow.api.WorkflowDefinition;
import org.opencastproject.workflow.api.WorkflowInstance;
import org.opencastproject.workflow.api.WorkflowOperationInstance;
import org.opencastproject.workflow.api.WorkflowService;
import org.opencastproject.workflow.api.WorkflowStateException;
import org.opencastproject.workflow.api.WorkflowUtil;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;

import net.fortuna.ical4j.model.property.RRule;

import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.codehaus.jettison.json.JSONException;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.text.ParseException;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TimeZone;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
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
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.media.SchemaProperty;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;

/**
 * The event endpoint acts as a facade for WorkflowService and Archive providing a unified query interface and result
 * set.
 * <p>
 * This first implementation uses the {@link org.opencastproject.assetmanager.api.AssetManager}. In a later iteration
 * the endpoint may abstract over the concrete archive.
 */
@Path("/admin-ng/event")
public abstract class AbstractEventEndpoint {

  /**
   * Scheduling JSON keys
   */
  public static final String SCHEDULING_AGENT_ID_KEY = "agentId";
  public static final String SCHEDULING_START_KEY = "start";
  public static final String SCHEDULING_END_KEY = "end";
  private static final String SCHEDULING_AGENT_CONFIGURATION_KEY = "agentConfiguration";
  public static final String SCHEDULING_PREVIOUS_AGENTID = "previousAgentId";
  public static final String SCHEDULING_PREVIOUS_PREVIOUSENTRIES = "previousEntries";

  private static final String WORKFLOW_ACTION_STOP = "STOP";

  /** The logging facility */
  static final Logger logger = LoggerFactory.getLogger(AbstractEventEndpoint.class);

  /** The configuration key that defines the default workflow definition */
  //TODO Move to a constants file instead of declaring it at the top of multiple files?
  protected static final String WORKFLOW_DEFINITION_DEFAULT = "org.opencastproject.workflow.default.definition";

  private static final String WORKFLOW_STATUS_TRANSLATION_PREFIX = "EVENTS.EVENTS.DETAILS.WORKFLOWS.OPERATION_STATUS.";

  /** The default time before a piece of signed content expires. 2 Hours. */
  protected static final long DEFAULT_URL_SIGNING_EXPIRE_DURATION = 2 * 60 * 60;

  public abstract AssetManager getAssetManager();

  public abstract WorkflowService getWorkflowService();

  public abstract OpenSearchIndex getIndex();

  public abstract JobEndpoint getJobService();

  public abstract SeriesEndpoint getSeriesEndpoint();

  public abstract AclService getAclService();

  public abstract EventCommentService getEventCommentService();

  public abstract SecurityService getSecurityService();

  public abstract IndexService getIndexService();

  public abstract AuthorizationService getAuthorizationService();

  public abstract SchedulerService getSchedulerService();

  public abstract CaptureAgentStateService getCaptureAgentStateService();

  public abstract AdminUIConfiguration getAdminUIConfiguration();

  public abstract long getUrlSigningExpireDuration();

  public abstract UrlSigningService getUrlSigningService();

  public abstract Boolean signWithClientIP();

  public abstract Boolean getOnlySeriesWithWriteAccessEventModal();

  public abstract Boolean getOnlyEventsWithWriteAccessEventsTab();

  public abstract UserDirectoryService getUserDirectoryService();

  public abstract ListProvidersService getListProvidersService();

  /** Default server URL */
  protected String serverUrl = "http://localhost:8080";

  /** Service url */
  protected String serviceUrl = null;

  /** The default workflow identifier, if one is configured */
  protected String defaultWorkflowDefinionId = null;

  /** The system user name (default set here for unit tests) */
  private String systemUserName = "opencast_system_account";

  /**
   * Activates REST service.
   *
   * @param cc
   *          ComponentContext
   */
  @Activate
  public void activate(ComponentContext cc) {
    if (cc != null) {
      String ccServerUrl = cc.getBundleContext().getProperty(OpencastConstants.SERVER_URL_PROPERTY);
      if (StringUtils.isNotBlank(ccServerUrl)) {
        this.serverUrl = ccServerUrl;
      }

      this.serviceUrl = (String) cc.getProperties().get(RestConstants.SERVICE_PATH_PROPERTY);

      String ccDefaultWorkflowDefinionId = StringUtils.trimToNull(cc.getBundleContext()
          .getProperty(WORKFLOW_DEFINITION_DEFAULT));

      if (StringUtils.isNotBlank(ccDefaultWorkflowDefinionId)) {
        this.defaultWorkflowDefinionId = ccDefaultWorkflowDefinionId;
      }

      systemUserName = SecurityUtil.getSystemUserName(cc);
    }
  }

  /* As the list of event ids can grow large, we use a POST request to avoid problems with too large query strings */
  @POST
  @Path("workflowProperties")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the workflow properties of events",
      description = "Returns workflow properties for the specified events"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returns the workflow properties for the events as JSON"),
      @ApiResponse(responseCode = "400", description = "The list of ids could not be parsed into a json list.")
  })
  public Response getEventWorkflowProperties(
      @Parameter(description = "A JSON array of ids of the events", required = true)
      @FormParam("eventIds") String eventIds
  ) throws UnauthorizedException {
    if (StringUtils.isBlank(eventIds)) {
      return Response.status(Response.Status.BAD_REQUEST).build();
    }

    List<String> ids;
    try {
      ids = toIdList(eventIds);
    } catch (JsonParseException | IllegalStateException | UnsupportedOperationException e) {
      logger.error("Unable to parse '{}'", eventIds, e);
      return Response.status(Response.Status.BAD_REQUEST).build();
    }

    final Map<String, Map<String, String>> eventWithProperties = getIndexService().getEventWorkflowProperties(ids);
    JsonObject jsonEvents = new JsonObject();

    for (Entry<String, Map<String, String>> event : eventWithProperties.entrySet()) {
      JsonObject jsonProperties = new JsonObject();

      for (Entry<String, String> property : event.getValue().entrySet()) {
        jsonProperties.add(property.getKey(), new JsonPrimitive(property.getValue()));
      }

      jsonEvents.add(event.getKey(), jsonProperties);
    }

    return okJson(jsonEvents);
  }


  @GET
  @Path("catalogAdapters")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the catalog UI adapters",
      description = "Returns the available catalog UI adapters as JSON"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returns the available catalog UI adapters as JSON")
  })
  public Response getCatalogAdapters() {
    JsonArray jsonAdapters = new JsonArray();
    for (EventCatalogUIAdapter adapter : getIndexService().getEventCatalogUIAdapters()) {
      JsonObject obj = new JsonObject();
      obj.addProperty("flavor", adapter.getFlavor().toString());
      obj.addProperty("title", adapter.getUITitle());
      jsonAdapters.add(obj);
    }

    return okJson(jsonAdapters);
  }

  @GET
  @Path("{eventId}")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get an event",
      description = "Returns the event by the given id as JSON"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returns the event as JSON"),
      @ApiResponse(responseCode = "404", description = "No event with this identifier was found.")
  })
  public Response getEventResponse(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String id
  ) throws Exception {
    Optional<Event> eventOpt = getIndexService().getEvent(id, getIndex());
    if (eventOpt.isPresent()) {
      Event event = eventOpt.get();
      event.updatePreview(getAdminUIConfiguration().getPreviewSubtype());
      JsonObject json = eventToJSON(event, Optional.empty(), Optional.empty());
      return okJson(json);
    }
    return notFound("Cannot find an event with id '%s'.", id);
  }

  @DELETE
  @Path("{eventId}")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Delete an event",
      description = "Delete a single event."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The event has been deleted."),
      @ApiResponse(
          responseCode = "202",
          description = "The event will be retracted and deleted afterwards."
      ),
      @ApiResponse(
          responseCode = "401",
          description = "If the current user is not authorized to perform this action"
      )
  })
  public Response deleteEvent(
      @Parameter(description = "The id of the event to delete.", required = true)
      @PathParam("eventId") String id
  ) throws UnauthorizedException, SearchIndexException {
    final Optional<Event> event = checkAgentAccessForEvent(id);
    if (event.isEmpty()) {
      return RestUtil.R.notFound(id);
    }
    final IndexService.EventRemovalResult result;
    try {
      result = getIndexService().removeEvent(event.get(), getAdminUIConfiguration().getRetractWorkflowId());
    } catch (UnauthorizedException e) {
      return Response.status(Response.Status.UNAUTHORIZED).build();
    } catch (WorkflowDatabaseException e) {
      logger.error("Workflow database is not reachable. This may be a temporary problem.");
      return RestUtil.R.serverError();
    } catch (NotFoundException e) {
      logger.error("Configured retract workflow not found. Check your configuration.");
      return RestUtil.R.serverError();
    }
    switch (result) {
      case SUCCESS:
        return Response.ok().build();
      case RETRACTING:
        return Response.accepted().build();
      case GENERAL_FAILURE:
        return Response.serverError().build();
      case NOT_FOUND:
        return RestUtil.R.notFound(id);
      default:
        throw new RuntimeException("Unknown EventRemovalResult type: " + result.name());
    }
  }

  @POST
  @Path("deleteEvents")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Delete multiple events",
      description = "Deletes a json list of events by their given ids e.g. [\"1dbe7255-e17d-4279-811d-a5c7ced689bf\", "
          + "\"04fae22b-0717-4f59-8b72-5f824f76d529\"]"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Events have been deleted"),
      @ApiResponse(responseCode = "400", description = "The list of ids could not be parsed into a json list."),
      @ApiResponse(responseCode = "401", description = "If the current user is not authorized to perform this action")
  })
  public Response deleteEvents(
      String eventIdsContent
  ) throws UnauthorizedException, SearchIndexException {
    if (StringUtils.isBlank(eventIdsContent)) {
      return Response.status(Response.Status.BAD_REQUEST).build();
    }

    JsonArray eventIdsJsonArray;
    try {
      eventIdsJsonArray = GsonUtil.gson().fromJson(eventIdsContent, JsonArray.class);
    } catch (JsonParseException | IllegalStateException e) {
      logger.error("Unable to parse '{}'", eventIdsContent, e);
      return Response.status(Response.Status.BAD_REQUEST).build();
    }

    BulkOperationResult result = new BulkOperationResult();

    for (Object eventIdObject : eventIdsJsonArray) {
      final String eventId = eventIdObject.toString();
      try {
        final Optional<Event> event = checkAgentAccessForEvent(eventId);
        if (event.isPresent()) {
          final IndexService.EventRemovalResult currentResult = getIndexService().removeEvent(event.get(),
                  getAdminUIConfiguration().getRetractWorkflowId());
          switch (currentResult) {
            case SUCCESS:
              result.addOk(eventId);
              break;
            case RETRACTING:
              result.addAccepted(eventId);
              break;
            case GENERAL_FAILURE:
              result.addServerError(eventId);
              break;
            case NOT_FOUND:
              result.addNotFound(eventId);
              break;
            default:
              throw new RuntimeException("Unknown EventRemovalResult type: " + currentResult.name());
          }
        } else {
          result.addNotFound(eventId);
        }
      } catch (UnauthorizedException e) {
        result.addUnauthorized(eventId);
      } catch (WorkflowDatabaseException e) {
        logger.error("Workflow database is not reachable. This may be a temporary problem.");
        return RestUtil.R.serverError();
      } catch (NotFoundException e) {
        logger.error("Configured retract workflow not found. Check your configuration.");
        return RestUtil.R.serverError();
      }
    }
    return Response.ok(result.toJson()).build();
  }

  @GET
  @Path("{eventId}/publications.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the publications tab data of an event",
      description = "Returns all the data related to the publications tab in the event details modal as JSON"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "Returns all the data related to the event publications tab as JSON"
      ),
      @ApiResponse(responseCode = "404", description = "No event with this identifier was found.")
  })
  public Response getEventPublicationsTab(
      @Parameter(description = "The event id (mediapackage id).", required = true)
      @PathParam("eventId") String id
  ) throws Exception {
    Optional<Event> optEvent = getIndexService().getEvent(id, getIndex());
    if (optEvent.isEmpty()) {
      return notFound("Cannot find an event with id '%s'.", id);
    }

    // Quick actions have been temporally removed from the publications tab
    // ---------------------------------------------------------------
    // List<JValue> actions = new ArrayList<JValue>();
    // List<WorkflowDefinition> workflowsDefinitions = getWorkflowService().listAvailableWorkflowDefinitions();
    // for (WorkflowDefinition wflDef : workflowsDefinitions) {
    // if (wflDef.containsTag(WORKFLOWDEF_TAG)) {
    //
    // actions.add(obj(f("id", v(wflDef.getId())), f("title", v(Opt.nul(wflDef.getTitle()).or(""))),
    // f("description", v(Opt.nul(wflDef.getDescription()).or(""))),
    // f("configuration_panel", v(Opt.nul(wflDef.getConfigurationPanel()).or("")))));
    // }
    // }

    Event event = optEvent.get();

    // Convert event publications to JSON array
    List<JsonObject> pubJSONList = eventPublicationsToJson(event);
    JsonArray publicationsJsonArray = new JsonArray();
    for (JsonObject pubJson : pubJSONList) {
      publicationsJsonArray.add(pubJson);
    }

    JsonObject result = new JsonObject();
    result.add("publications", publicationsJsonArray);

    // Add start-date and end-date as strings, or blank if null
    String startDate = event.getRecordingStartDate() != null
        ? event.getRecordingStartDate().toString()
        : "";
    String endDate = event.getRecordingEndDate() != null
        ? event.getRecordingEndDate().toString()
        : "";
    result.addProperty("start-date", startDate);
    result.addProperty("end-date", endDate);

    return okJson(result);
  }

  private List<JsonObject> eventPublicationsToJson(Event event) {
    List<JsonObject> pubJSON = new ArrayList<>();

    for (Publication publication : event.getPublications()) {
      if (internalChannelFilter.test(publication)) {
        pubJSON.add(publicationToJson.apply(publication));
      }
    }

    return pubJSON;
  }

  private List<JsonObject> eventCommentsToJson(List<EventComment> comments) {
    List<JsonObject> commentArr = new ArrayList<>();

    for (EventComment c : comments) {
      JsonObject author = new JsonObject();
      author.addProperty("name", c.getAuthor().getName());
      if (c.getAuthor().getEmail() != null) {
        author.addProperty("email", c.getAuthor().getEmail());
      } else {
        author.add("email", null);
      }
      author.addProperty("username", c.getAuthor().getUsername());

      JsonArray replies = new JsonArray();
      List<JsonObject> replyJsonList = eventCommentRepliesToJson(c.getReplies());
      for (JsonObject replyJson : replyJsonList) {
        replies.add(replyJson);
      }

      JsonObject commentJson = new JsonObject();
      commentJson.addProperty("reason", c.getReason());
      commentJson.addProperty("resolvedStatus", c.isResolvedStatus());
      commentJson.addProperty("modificationDate", c.getModificationDate().toInstant().toString());
      commentJson.add("replies", replies);
      commentJson.add("author", author);
      commentJson.addProperty("id", c.getId().get());
      commentJson.addProperty("text", c.getText());
      commentJson.addProperty("creationDate", c.getCreationDate().toInstant().toString());

      commentArr.add(commentJson);
    }

    return commentArr;
  }

  private List<JsonObject> eventCommentRepliesToJson(List<EventCommentReply> replies) {
    List<JsonObject> repliesArr = new ArrayList<>();

    for (EventCommentReply r : replies) {
      JsonObject author = new JsonObject();
      author.addProperty("name", r.getAuthor().getName());
      if (r.getAuthor().getEmail() != null) {
        author.addProperty("email", r.getAuthor().getEmail());
      } else {
        author.add("email", null);
      }
      author.addProperty("username", r.getAuthor().getUsername());

      JsonObject replyJson = new JsonObject();
      replyJson.addProperty("id", r.getId().get());
      replyJson.addProperty("text", r.getText());
      replyJson.addProperty("creationDate", r.getCreationDate().toInstant().toString());
      replyJson.addProperty("modificationDate", r.getModificationDate().toInstant().toString());
      replyJson.add("author", author);

      repliesArr.add(replyJson);
    }

    return repliesArr;
  }

  @GET
  @Path("{eventId}/scheduling.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the scheduling metadata of an event",
      description = "Returns all of the scheduling metadata for an event"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "Returns all the data related to the event scheduling tab as JSON"
      ),
      @ApiResponse(responseCode = "404", description = "No event with this identifier was found.")
  })
  public Response getEventScheduling(
      @Parameter(description = "The event id (mediapackage id).", required = true)
      @PathParam("eventId") String eventId
  ) throws NotFoundException, UnauthorizedException, SearchIndexException {
    Optional<Event> optEvent = getIndexService().getEvent(eventId, getIndex());
    if (optEvent.isEmpty()) {
      return notFound("Cannot find an event with id '%s'.", eventId);
    }

    try {
      TechnicalMetadata technicalMetadata = getSchedulerService().getTechnicalMetadata(eventId);
      return okJson(technicalMetadataToJson(technicalMetadata));
    } catch (SchedulerException e) {
      logger.error("Unable to get technical metadata for event with id {}", eventId);
      throw new WebApplicationException(e, SC_INTERNAL_SERVER_ERROR);
    }
  }

  @POST
  @Path("scheduling.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the scheduling metadata of multiple events",
      description = "Returns all of the scheduling metadata for a list of events"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "Returns all the data related to the event scheduling tab as JSON"
      ),
      @ApiResponse(responseCode = "404", description = "No event with this identifier was found.")
  })
  public Response getEventsScheduling(
      @Parameter(description = "An array of event IDs (mediapackage id)", required = true)
      @FormParam("eventIds") final List<String> eventIds,
      @Parameter(
          description = "Whether events that are not really scheduled "
              + "events should be ignored or produce an error",
          required = true
      )
      @FormParam("ignoreNonScheduled") final boolean ignoreNonScheduled
  ) {
    JsonArray fields = new JsonArray();

    for (final String eventId : eventIds) {
      try {
        fields.add(technicalMetadataToJson(getSchedulerService().getTechnicalMetadata(eventId)));
      } catch (final NotFoundException e) {
        if (!ignoreNonScheduled) {
          logger.warn("Unable to find id {}", eventId, e);
          return notFound("Cannot find an event with id '%s'.", eventId);
        }
      } catch (final UnauthorizedException e) {
        logger.warn("Unauthorized access to event ID {}", eventId, e);
        return Response.status(Status.BAD_REQUEST).build();
      } catch (final SchedulerException e) {
        logger.warn("Scheduler exception accessing event ID {}", eventId, e);
        return Response.status(Status.BAD_REQUEST).build();
      }
    }
    return okJson(fields);
  }

  @PUT
  @Path("{eventId}/scheduling")
  @Operation(
      summary = "Update the scheduling information of an event",
      description = "Updates the scheduling information of an event"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "400",
          description = "The required params were missing in the request."
      ),
      @ApiResponse(responseCode = "404", description = "If the event has not been found."),
      @ApiResponse(responseCode = "204", description = "The method doesn't return any content")
  })
  public Response updateEventScheduling(
      @Parameter(description = "The event identifier", required = true)
      @PathParam("eventId") String eventId,
      @Parameter(description = "The updated scheduling (JSON object)", required = true)
      @FormParam("scheduling") String scheduling
  ) throws NotFoundException, UnauthorizedException, SearchIndexException, IndexServiceException {
    if (StringUtils.isBlank(scheduling)) {
      return RestUtil.R.badRequest("Missing parameters");
    }

    try {
      final Event event = getEventOrThrowNotFoundException(eventId);
      updateEventScheduling(scheduling, event);
      return Response.noContent().build();
    } catch (JSONException e) {
      return RestUtil.R.badRequest("The scheduling object is not valid");
    } catch (ParseException e) {
      return RestUtil.R.badRequest("The UTC dates in the scheduling object is not valid");
    } catch (SchedulerException e) {
      logger.error("Unable to update scheduling technical metadata of event {}", eventId, e);
      throw new WebApplicationException(e, SC_INTERNAL_SERVER_ERROR);
    } catch (IllegalStateException e) {
      return RestUtil.R.badRequest(e.getMessage());
    }
  }

  private void updateEventScheduling(String scheduling, Event event) throws NotFoundException, UnauthorizedException,
          SchedulerException, JSONException, ParseException, SearchIndexException, IndexServiceException {
    final TechnicalMetadata technicalMetadata = getSchedulerService().getTechnicalMetadata(event.getIdentifier());
    final org.codehaus.jettison.json.JSONObject schedulingJson = new org.codehaus.jettison.json.JSONObject(
            scheduling);
    Optional<String> agentId = Optional.empty();
    if (schedulingJson.has(SCHEDULING_AGENT_ID_KEY)) {
      agentId = Optional.of(schedulingJson.getString(SCHEDULING_AGENT_ID_KEY));
      logger.trace("Updating agent id of event '{}' from '{}' to '{}'",
              event.getIdentifier(), technicalMetadata.getAgentId(), agentId);
    }

    Optional<String> previousAgentId = Optional.empty();
    if (schedulingJson.has(SCHEDULING_PREVIOUS_AGENTID)) {
      previousAgentId = Optional.of(schedulingJson.getString(SCHEDULING_PREVIOUS_AGENTID));
    }

    Optional<String> previousAgentInputs = Optional.empty();
    Optional<String> agentInputs = Optional.empty();
    if (agentId.isPresent() && previousAgentId.isPresent()) {
      Agent previousAgent = getCaptureAgentStateService().getAgent(previousAgentId.get());
      Agent agent = getCaptureAgentStateService().getAgent(agentId.get());

      previousAgentInputs = Optional.ofNullable(previousAgent.getCapabilities().getProperty(
          CaptureParameters.CAPTURE_DEVICE_NAMES));
      agentInputs = Optional.ofNullable(agent.getCapabilities().getProperty(CaptureParameters.CAPTURE_DEVICE_NAMES));
    }

    // Check if we are allowed to re-schedule on this agent
    checkAgentAccessForAgent(technicalMetadata.getAgentId());
    if (agentId.isPresent()) {
      checkAgentAccessForAgent(agentId.get());
    }

    Optional<Date> start = Optional.empty();
    if (schedulingJson.has(SCHEDULING_START_KEY)) {
      start = Optional.of(new Date(DateTimeSupport.fromUTC(schedulingJson.getString(SCHEDULING_START_KEY))));
      logger.trace("Updating start time of event '{}' id from '{}' to '{}'",
          event.getIdentifier(), DateTimeSupport.toUTC(technicalMetadata.getStartDate().getTime()),
          DateTimeSupport.toUTC(start.get().getTime()));
    }

    Optional<Date> end = Optional.empty();
    if (schedulingJson.has(SCHEDULING_END_KEY)) {
      end = Optional.of(new Date(DateTimeSupport.fromUTC(schedulingJson.getString(SCHEDULING_END_KEY))));
      logger.trace("Updating end time of event '{}' id from '{}' to '{}'",
          event.getIdentifier(), DateTimeSupport.toUTC(technicalMetadata.getEndDate().getTime()),
          DateTimeSupport.toUTC(end.get().getTime()));
    }

    Optional<Map<String, String>> agentConfiguration = Optional.empty();
    if (schedulingJson.has(SCHEDULING_AGENT_CONFIGURATION_KEY)) {
      agentConfiguration = Optional.of(JSONUtils.toMap(schedulingJson.getJSONObject(
          SCHEDULING_AGENT_CONFIGURATION_KEY)));
      logger.trace("Updating agent configuration of event '{}' id from '{}' to '{}'",
          event.getIdentifier(), technicalMetadata.getCaptureAgentConfiguration(), agentConfiguration);
    }

    Optional<Map<String, String>> previousAgentInputMethods = Optional.empty();
    if (schedulingJson.has(SCHEDULING_PREVIOUS_PREVIOUSENTRIES)) {
      previousAgentInputMethods = Optional.of(
              JSONUtils.toMap(schedulingJson.getJSONObject(SCHEDULING_PREVIOUS_PREVIOUSENTRIES)));
    }

    // If we had previously selected an agent, and both the old and new agent have the same set of input channels,
    // copy which input channels are active to the new agent
    if (previousAgentInputs.isPresent() && previousAgentInputs.isPresent() && agentInputs.isPresent()) {
      Map<String, String> map = previousAgentInputMethods.get();
      String mapAsString = map.keySet().stream()
              .collect(Collectors.joining(","));
      String previousInputs = mapAsString;

      if (previousAgentInputs.equals(agentInputs)) {
        final Map<String, String> configMap = new HashMap<>(agentConfiguration.get());
        configMap.put(CaptureParameters.CAPTURE_DEVICE_NAMES, previousInputs);
        agentConfiguration = Optional.of(configMap);
      }
    }

    if ((start.isPresent() || end.isPresent())
            && end.orElse(technicalMetadata.getEndDate()).before(start.orElse(technicalMetadata.getStartDate()))) {
      throw new IllegalStateException("The end date is before the start date");
    }

    if (!start.isEmpty() || !end.isEmpty() || !agentId.isEmpty() || !agentConfiguration.isEmpty()) {
      getSchedulerService().updateEvent(event.getIdentifier(), start, end, agentId, Optional.empty(), Optional.empty(),
          Optional.empty(), agentConfiguration);
    }
  }

  private Event getEventOrThrowNotFoundException(final String eventId) throws NotFoundException, SearchIndexException {
    Optional<Event> optEvent = getIndexService().getEvent(eventId, getIndex());
    if (optEvent.isPresent()) {
      return optEvent.get();
    } else {
      throw new NotFoundException(format("Cannot find an event with id '%s'.", eventId));
    }
  }

  @GET
  @Path("{eventId}/comments")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the comments of an event",
      description = "Returns all the data related to the comments tab in the event details modal as JSON"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "Returns all the data related to the event comments tab as JSON"
      ),
      @ApiResponse(responseCode = "404", description = "No event with this identifier was found.")
  })
  public Response getEventComments(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String eventId
  ) throws Exception {
    Optional<Event> optEvent = getIndexService().getEvent(eventId, getIndex());
    if (optEvent.isEmpty()) {
      return notFound("Cannot find an event with id '%s'.", eventId);
    }

    try {
      List<EventComment> comments = getEventCommentService().getComments(eventId);
      JsonArray commentArr = new JsonArray();
      for (EventComment c : comments) {
        commentArr.add(c.toJson());
      }
      return Response.ok(commentArr.toString(), MediaType.APPLICATION_JSON_TYPE)
              .build();
    } catch (EventCommentException e) {
      logger.error("Unable to get comments from event {}", eventId, e);
      throw new WebApplicationException(e);
    }
  }

  @GET
  @Path("{eventId}/hasActiveTransaction")
  @Produces(MediaType.TEXT_PLAIN)
  @Operation(
      summary = "Check whether an event has an active transaction",
      description = "Returns whether there is currently a transaction in progress for the given event"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "Returns whether there is currently a transaction in progress for the given event"
      ),
      @ApiResponse(responseCode = "404", description = "No event with this identifier was found.")
  })
  public Response hasActiveTransaction(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String eventId
  ) throws Exception {
    Optional<Event> optEvent = getIndexService().getEvent(eventId, getIndex());
    if (optEvent.isEmpty()) {
      return notFound("Cannot find an event with id '%s'.", eventId);
    }

    JsonObject json = new JsonObject();
    json.addProperty("active", WorkflowUtil.isActive(optEvent.get().getWorkflowState()));

    return Response.ok(json.toString()).build();
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("{eventId}/comment/{commentId}")
  @Operation(
      summary = "Get a comment of an event",
      description = "Returns the comment with the given identifier"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The comment as JSON."),
      @ApiResponse(
          responseCode = "404",
          description = "No event or comment with this identifier was found."
      )
  })
  public Response getEventComment(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String eventId,
      @Parameter(description = "The comment identifier", required = true)
      @PathParam("commentId") long commentId
  ) throws NotFoundException, Exception {
    Optional<Event> optEvent = getIndexService().getEvent(eventId, getIndex());
    if (optEvent.isEmpty()) {
      return notFound("Cannot find an event with id '%s'.", eventId);
    }

    try {
      EventComment comment = getEventCommentService().getComment(commentId);
      return Response.ok(comment.toJson().toString()).build();
    } catch (NotFoundException e) {
      throw e;
    } catch (Exception e) {
      logger.error("Could not retrieve comment {}", commentId, e);
      throw new WebApplicationException(e);
    }
  }

  @PUT
  @Path("{eventId}/comment/{commentId}")
  @Operation(
      summary = "Update a comment of an event",
      description = "Updates an event comment"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "404",
          description = "The event or comment to update has not been found."
      ),
      @ApiResponse(responseCode = "200", description = "The updated comment as JSON.")
  })
  public Response updateEventComment(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String eventId,
      @Parameter(description = "The comment identifier", required = true)
      @PathParam("commentId") long commentId,
      @Parameter(description = "The comment text")
      @FormParam("text") String text,
      @Parameter(description = "The comment reason")
      @FormParam("reason") String reason,
      @Parameter(description = "The comment resolved status")
      @FormParam("resolved") Boolean resolved
  ) throws Exception {
    Optional<Event> optEvent = getIndexService().getEvent(eventId, getIndex());
    if (optEvent.isEmpty()) {
      return notFound("Cannot find an event with id '%s'.", eventId);
    }

    try {
      EventComment dto = getEventCommentService().getComment(commentId);

      if (StringUtils.isNotBlank(text)) {
        text = text.trim();
      } else {
        text = dto.getText();
      }

      if (StringUtils.isNotBlank(reason)) {
        reason = reason.trim();
      } else {
        reason = dto.getReason();
      }

      if (resolved == null) {
        resolved = dto.isResolvedStatus();
      }

      EventComment updatedComment = EventComment.create(dto.getId(), eventId,
              getSecurityService().getOrganization().getId(), text, dto.getAuthor(), reason, resolved,
              dto.getCreationDate(), new Date(), dto.getReplies());

      updatedComment = getEventCommentService().updateComment(updatedComment);
      List<EventComment> comments = getEventCommentService().getComments(eventId);
      getIndexService().updateCommentCatalog(optEvent.get(), comments);
      return Response.ok(updatedComment.toJson().toString()).build();
    } catch (NotFoundException e) {
      throw e;
    } catch (Exception e) {
      logger.error("Unable to update the comments catalog on event {}", eventId, e);
      throw new WebApplicationException(e);
    }
  }

  @POST
  @Path("{eventId}/access")
  @Operation(
      summary = "Apply an ACL to an event",
      description = "Immediate application of an ACL to an event"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The ACL has been successfully applied"),
      @ApiResponse(responseCode = "400", description = "Unable to parse the given ACL"),
      @ApiResponse(responseCode = "404", description = "The the event has not been found"),
      @ApiResponse(responseCode = "401", description = "Not authorized to perform this action"),
      @ApiResponse(responseCode = "500", description = "Internal error")
  })
  public Response applyAclToEvent(
      @Parameter(description = "The event ID", required = true)
      @PathParam("eventId") String eventId,
      @Parameter(description = "The ACL to apply", required = true)
      @FormParam("acl") String acl
  ) throws NotFoundException, UnauthorizedException, SearchIndexException, IndexServiceException {
    final AccessControlList accessControlList;
    try {
      accessControlList = AccessControlParser.parseAcl(acl);
    } catch (Exception e) {
      logger.warn("Unable to parse ACL '{}'", acl);
      return badRequest();
    }

    try {
      final Optional<Event> optEvent = getIndexService().getEvent(eventId, getIndex());
      if (optEvent.isEmpty()) {
        logger.warn("Unable to find the event '{}'", eventId);
        return notFound();
      }

      Source eventSource = getIndexService().getEventSource(optEvent.get());
      if (eventSource == Source.ARCHIVE) {
        Optional<MediaPackage> mediaPackage = getAssetManager().getMediaPackage(eventId);
        Optional<AccessControlList> aclOpt = Optional.ofNullable(accessControlList);
        // the episode service is the source of authority for the retrieval of media packages
        if (mediaPackage.isPresent()) {
          MediaPackage episodeSvcMp = mediaPackage.get();
          aclOpt.ifPresentOrElse(
              aclPresent -> {
                try {
                  MediaPackage mp = getAuthorizationService()
                      .setAcl(episodeSvcMp, AclScope.Episode, aclPresent)
                      .getA();
                  getAssetManager().takeSnapshot(mp);
                } catch (MediaPackageException e) {
                  logger.error("Error getting ACL from media package", e);
                }
              },
              () -> {
                MediaPackage mp = getAuthorizationService().removeAcl(episodeSvcMp, AclScope.Episode);
                getAssetManager().takeSnapshot(mp);
              }
          );
          return ok();
        }
        logger.warn("Unable to find the event '{}'", eventId);
        return notFound();
      } else if (eventSource == Source.WORKFLOW) {
        logger.warn("An ACL cannot be edited while an event is part of a current workflow because it might"
                + " lead to inconsistent ACLs i.e. changed after distribution so that the old ACL is still "
                + "being used by the distribution channel.");
        JsonObject json = new JsonObject();
        json.addProperty("Error", "Unable to edit an ACL for a current workflow.");
        return conflict(json.toString());
      } else {
        MediaPackage mediaPackage = getIndexService().getEventMediapackage(optEvent.get());
        mediaPackage = getAuthorizationService().setAcl(mediaPackage, AclScope.Episode, accessControlList).getA();
        // We could check agent access here if we want to forbid updating ACLs for users without access.
        getSchedulerService().updateEvent(eventId, Optional.empty(), Optional.empty(), Optional.empty(),
            Optional.empty(), Optional.of(mediaPackage), Optional.empty(), Optional.empty());
        return ok();
      }
    } catch (MediaPackageException e) {
      if (e.getCause() instanceof UnauthorizedException) {
        return forbidden();
      }
      logger.error("Error applying acl '{}' to event '{}'", accessControlList, eventId, e);
      return serverError();
    } catch (SchedulerException e) {
      logger.error("Error applying ACL to scheduled event {}", eventId, e);
      return serverError();
    }
  }

  @POST
  @Path("{eventId}/comment")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Create a comment on an event",
      description = "Creates a comment related to the event given by the identifier"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "201", description = "The comment has been created."),
      @ApiResponse(responseCode = "400", description = "If no text ist set."),
      @ApiResponse(responseCode = "404", description = "No event with this identifier was found.")
  })
  public Response createEventComment(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String eventId,
      @Parameter(description = "The comment text", required = true)
      @FormParam("text") String text,
      @Parameter(description = "The comment reason")
      @FormParam("reason") String reason,
      @Parameter(description = "The comment resolved status")
      @FormParam("resolved") Boolean resolved
  ) throws Exception {
    Optional<Event> optEvent = getIndexService().getEvent(eventId, getIndex());
    if (optEvent.isEmpty()) {
      return notFound("Cannot find an event with id '%s'.", eventId);
    }

    if (StringUtils.isBlank(text)) {
      return Response.status(Status.BAD_REQUEST).build();
    }

    User author = getSecurityService().getUser();
    try {
      EventComment createdComment = EventComment.create(Optional.<Long> empty(), eventId,
              getSecurityService().getOrganization().getId(), text, author, reason, BooleanUtils.toBoolean(reason));
      createdComment = getEventCommentService().updateComment(createdComment);
      List<EventComment> comments = getEventCommentService().getComments(eventId);
      getIndexService().updateCommentCatalog(optEvent.get(), comments);
      return Response.created(getCommentUrl(eventId, createdComment.getId().get()))
              .entity(createdComment.toJson().toString()).build();
    } catch (Exception e) {
      logger.error("Unable to create a comment on the event {}", eventId, e);
      throw new WebApplicationException(e);
    }
  }

  @POST
  @Path("{eventId}/comment/{commentId}")
  @Operation(
      summary = "Resolve a comment of an event",
      description = "Resolves an event comment"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "404",
          description = "The event or comment to resolve has not been found."
      ),
      @ApiResponse(responseCode = "200", description = "The resolved comment as JSON.")
  })
  public Response resolveEventComment(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String eventId,
      @Parameter(description = "The comment identifier", required = true)
      @PathParam("commentId") long commentId
  ) throws Exception {
    Optional<Event> optEvent = getIndexService().getEvent(eventId, getIndex());
    if (optEvent.isEmpty()) {
      return notFound("Cannot find an event with id '%s'.", eventId);
    }

    try {
      EventComment dto = getEventCommentService().getComment(commentId);
      EventComment updatedComment = EventComment.create(dto.getId(), dto.getEventId(), dto.getOrganization(),
              dto.getText(), dto.getAuthor(), dto.getReason(), true, dto.getCreationDate(), new Date(),
              dto.getReplies());

      updatedComment = getEventCommentService().updateComment(updatedComment);
      List<EventComment> comments = getEventCommentService().getComments(eventId);
      getIndexService().updateCommentCatalog(optEvent.get(), comments);
      return Response.ok(updatedComment.toJson().toString()).build();
    } catch (NotFoundException e) {
      throw e;
    } catch (Exception e) {
      logger.error("Could not resolve comment {}", commentId, e);
      throw new WebApplicationException(e);
    }
  }

  @DELETE
  @Path("{eventId}/comment/{commentId}")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Delete a comment of an event",
      description = "Deletes a event related comment by its identifier"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "The event related comment has been deleted."),
      @ApiResponse(responseCode = "404", description = "No event or comment with this identifier was found.")
  })
  public Response deleteEventComment(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String eventId,
      @Parameter(description = "The comment id", required = true)
      @PathParam("commentId") long commentId
  ) throws Exception {
    Optional<Event> optEvent = getIndexService().getEvent(eventId, getIndex());
    if (optEvent.isEmpty()) {
      return notFound("Cannot find an event with id '%s'.", eventId);
    }

    try {
      getEventCommentService().deleteComment(commentId);
      List<EventComment> comments = getEventCommentService().getComments(eventId);
      getIndexService().updateCommentCatalog(optEvent.get(), comments);
      return Response.noContent().build();
    } catch (NotFoundException e) {
      throw e;
    } catch (Exception e) {
      logger.error("Unable to delete comment {} on event {}", commentId, eventId, e);
      throw new WebApplicationException(e);
    }
  }

  @DELETE
  @Path("{eventId}/comment/{commentId}/{replyId}")
  @Operation(
      summary = "Delete a reply to an event comment",
      description = "Delete an event comment reply"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "404",
          description = "No event comment or reply with this identifier was found."
      ),
      @ApiResponse(responseCode = "200", description = "The updated comment as JSON.")
  })
  public Response deleteEventCommentReply(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String eventId,
      @Parameter(description = "The comment identifier", required = true)
      @PathParam("commentId") long commentId,
      @Parameter(description = "The comment reply identifier", required = true)
      @PathParam("replyId") long replyId
  ) throws Exception {
    Optional<Event> optEvent = getIndexService().getEvent(eventId, getIndex());
    if (optEvent.isEmpty()) {
      return notFound("Cannot find an event with id '%s'.", eventId);
    }

    EventComment comment = null;
    EventCommentReply reply = null;
    try {
      comment = getEventCommentService().getComment(commentId);
      for (EventCommentReply r : comment.getReplies()) {
        if (r.getId().isEmpty() || replyId != r.getId().get().longValue()) {
          continue;
        }
        reply = r;
        break;
      }

      if (reply == null) {
        throw new NotFoundException("Reply with id " + replyId + " not found!");
      }

      comment.removeReply(reply);

      EventComment updatedComment = getEventCommentService().updateComment(comment);
      List<EventComment> comments = getEventCommentService().getComments(eventId);
      getIndexService().updateCommentCatalog(optEvent.get(), comments);
      return Response.ok(updatedComment.toJson().toString()).build();
    } catch (NotFoundException e) {
      throw e;
    } catch (Exception e) {
      logger.warn("Could not remove event comment reply {} from comment {}", replyId, commentId, e);
      throw new WebApplicationException(e);
    }
  }

  @PUT
  @Path("{eventId}/comment/{commentId}/{replyId}")
  @Operation(
      summary = "Update a reply to an event comment",
      description = "Updates an event comment reply"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "404",
          description = "The event or comment to extend with a reply or the reply has not been found."
      ),
      @ApiResponse(responseCode = "400", description = "If no text is set."),
      @ApiResponse(responseCode = "200", description = "The updated comment as JSON.")
  })
  public Response updateEventCommentReply(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String eventId,
      @Parameter(description = "The comment identifier", required = true)
      @PathParam("commentId") long commentId,
      @Parameter(description = "The comment reply identifier", required = true)
      @PathParam("replyId") long replyId,
      @Parameter(description = "The comment reply text", required = true)
      @FormParam("text") String text
  ) throws Exception {
    if (StringUtils.isBlank(text)) {
      return Response.status(Status.BAD_REQUEST).build();
    }

    Optional<Event> optEvent = getIndexService().getEvent(eventId, getIndex());
    if (optEvent.isEmpty()) {
      return notFound("Cannot find an event with id '%s'.", eventId);
    }

    EventComment comment = null;
    EventCommentReply reply = null;
    try {
      comment = getEventCommentService().getComment(commentId);
      for (EventCommentReply r : comment.getReplies()) {
        if (r.getId().isEmpty() || replyId != r.getId().get().longValue()) {
          continue;
        }
        reply = r;
        break;
      }

      if (reply == null) {
        throw new NotFoundException("Reply with id " + replyId + " not found!");
      }

      EventCommentReply updatedReply = EventCommentReply.create(reply.getId(), text.trim(), reply.getAuthor(),
              reply.getCreationDate(), new Date());
      comment.removeReply(reply);
      comment.addReply(updatedReply);

      EventComment updatedComment = getEventCommentService().updateComment(comment);
      List<EventComment> comments = getEventCommentService().getComments(eventId);
      getIndexService().updateCommentCatalog(optEvent.get(), comments);
      return Response.ok(updatedComment.toJson().toString()).build();
    } catch (NotFoundException e) {
      throw e;
    } catch (Exception e) {
      logger.warn("Could not update event comment reply {} from comment {}", replyId, commentId, e);
      throw new WebApplicationException(e);
    }
  }

  @POST
  @Path("{eventId}/comment/{commentId}/reply")
  @Operation(
      summary = "Create a reply to an event comment",
      description = "Creates an event comment reply"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "404",
          description = "The event or comment to extend with a reply has not been found."
      ),
      @ApiResponse(responseCode = "400", description = "If no text is set."),
      @ApiResponse(responseCode = "200", description = "The updated comment as JSON.")
  })
  public Response createEventCommentReply(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String eventId,
      @Parameter(description = "The comment identifier", required = true)
      @PathParam("commentId") long commentId,
      @Parameter(description = "The comment reply text", required = true)
      @FormParam("text") String text,
      @Parameter(
          description = "Flag defining if this reply solve or not the comment."
      )
      @FormParam("resolved") Boolean resolved
  ) throws Exception {
    if (StringUtils.isBlank(text)) {
      return Response.status(Status.BAD_REQUEST).build();
    }

    Optional<Event> optEvent = getIndexService().getEvent(eventId, getIndex());
    if (optEvent.isEmpty()) {
      return notFound("Cannot find an event with id '%s'.", eventId);
    }

    EventComment comment = null;
    try {
      comment = getEventCommentService().getComment(commentId);
      EventComment updatedComment;

      if (resolved != null && resolved) {
        // If the resolve flag is set to true, change to comment to resolved
        updatedComment = EventComment.create(comment.getId(), comment.getEventId(), comment.getOrganization(),
                comment.getText(), comment.getAuthor(), comment.getReason(), true, comment.getCreationDate(),
                new Date(), comment.getReplies());
      } else {
        updatedComment = comment;
      }

      User author = getSecurityService().getUser();
      EventCommentReply reply = EventCommentReply.create(Optional.<Long> empty(), text, author);
      updatedComment.addReply(reply);

      updatedComment = getEventCommentService().updateComment(updatedComment);
      List<EventComment> comments = getEventCommentService().getComments(eventId);
      getIndexService().updateCommentCatalog(optEvent.get(), comments);
      return Response.ok(updatedComment.toJson().toString()).build();
    } catch (Exception e) {
      logger.warn("Could not create event comment reply on comment {}", comment, e);
      throw new WebApplicationException(e);
    }
  }

  /**
   * Removes emtpy series titles from the collection of the isPartOf Field
   * @param ml the list to modify
   */
  private void removeSeriesWithNullTitlesFromFieldCollection(MetadataList ml) {
    // get Series MetadataField from MetadataList
    MetadataField seriesField = Optional.ofNullable(ml.getMetadataList().get("dublincore/episode"))
            .flatMap(titledMetadataCollection -> Optional.ofNullable(titledMetadataCollection.getCollection()))
            .flatMap(dcMetadataCollection -> Optional.ofNullable(dcMetadataCollection.getOutputFields()))
            .flatMap(metadataFields -> Optional.ofNullable(metadataFields.get("isPartOf")))
            .orElse(null);
    if (seriesField == null || seriesField.getCollection() == null) {
      return;
    }

    // Remove null keys
    Map<String, String> seriesCollection = seriesField.getCollection();
    seriesCollection.remove(null);
    seriesField.setCollection(seriesCollection);

    return;
  }

  @GET
  @Path("{eventId}/metadata.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the metadata of an event",
      description = "Returns all the data related to the metadata tab in the event details modal as JSON"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "Returns all the data related to the event metadata tab as JSON"
      ),
      @ApiResponse(responseCode = "404", description = "No event with this identifier was found.")
  })
  public Response getEventMetadata(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String eventId
  ) throws Exception {
    Optional<Event> optEvent = getIndexService().getEvent(eventId, getIndex());
    if (optEvent.isEmpty()) {
      return notFound("Cannot find an event with id '%s'.", eventId);
    }
    Event event = optEvent.get();
    MetadataList metadataList = new MetadataList();

    // Load extended metadata
    List<EventCatalogUIAdapter> extendedCatalogUIAdapters = getIndexService().getExtendedEventCatalogUIAdapters();
    if (!extendedCatalogUIAdapters.isEmpty()) {
      MediaPackage mediaPackage;
      try {
        mediaPackage = getIndexService().getEventMediapackage(event);
      } catch (IndexServiceException e) {
        if (e.getCause() instanceof NotFoundException) {
          return notFound("Cannot find data for event %s", eventId);
        } else if (e.getCause() instanceof UnauthorizedException) {
          return Response.status(Status.FORBIDDEN).entity("Not authorized to access " + eventId).build();
        }
        logger.error("Internal error when trying to access metadata for " + eventId, e);
        return serverError();
      }

      for (EventCatalogUIAdapter extendedCatalogUIAdapter : extendedCatalogUIAdapters) {
        metadataList.add(extendedCatalogUIAdapter, extendedCatalogUIAdapter.getFields(mediaPackage));
      }
    }

    // Load common metadata
    // We do this after extended metadata because we want to overwrite any extended metadata adapters with the same
    // flavor instead of the other way around.
    EventCatalogUIAdapter eventCatalogUiAdapter = getIndexService().getCommonEventCatalogUIAdapter();
    DublinCoreMetadataCollection metadataCollection = eventCatalogUiAdapter.getRawFields(getCollectionQueryDisable());
    EventUtils.setEventMetadataValues(event, metadataCollection);
    metadataList.add(eventCatalogUiAdapter, metadataCollection);

    // remove series with empty titles from the collection of the isPartOf field as these can't be converted to json
    removeSeriesWithNullTitlesFromFieldCollection(metadataList);

    // lock metadata?
    final String wfState = event.getWorkflowState();
    if (wfState != null && WorkflowUtil.isActive(wfState)) {
      metadataList.setLocked(Locked.WORKFLOW_RUNNING);
    }

    return okJson(MetadataJson.listToJson(metadataList, true, false));
  }

  /**
   * Create a special query that disables filling the collection of a series, for performance reasons.
   * The collection can still be fetched via the listprovider endpoint.
   *
   * @return a map with resource list queries belonging to metadata fields
   */
  private Map getCollectionQueryDisable() {
    HashMap<String, ResourceListQuery> collectionQueryOverrides = new HashMap();
    SeriesListQuery seriesListQuery = new SeriesListQuery();
    seriesListQuery.setLimit(0);
    collectionQueryOverrides.put(DublinCore.PROPERTY_IS_PART_OF.getLocalName(), seriesListQuery);
    return collectionQueryOverrides;
  }

  @POST  // use POST instead of GET because of a possibly long list of ids
  @Path("events/metadata.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the metadata of multiple events",
      description = "Returns all the data related to the edit events metadata modal as JSON"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "Returns all the data related to the edit events metadata modal as JSON"
      ),
      @ApiResponse(
          responseCode = "404",
          description = "No events to update, either not found or with running workflow, details in "
              + "response body."
      )
  })
  public Response getEventsMetadata(
      @Parameter(description = "The event ids", required = true)
      @FormParam("eventIds") String eventIds
  ) throws Exception {
    if (StringUtils.isBlank(eventIds)) {
      return badRequest("Event ids can't be empty");
    }

    List<String> ids;
    try {
      ids = toIdList(eventIds);
    } catch (JsonParseException | IllegalStateException | UnsupportedOperationException e) {
      logger.error("Unable to parse '{}'", eventIds, e);
      return badRequest("Unable to parse event ids");
    }

    Set<String> eventsNotFound = new HashSet();
    Set<String> eventsWithRunningWorkflow = new HashSet();
    Set<String> eventsMerged = new HashSet();

    // collect the metadata of all events
    List<DublinCoreMetadataCollection> collectedMetadata = new ArrayList();
    for (String eventId: ids) {
      Optional<Event> optEvent = getIndexService().getEvent(eventId, getIndex());
      // not found?
      if (optEvent.isEmpty()) {
        eventsNotFound.add(eventId);
        continue;
      }

      Event event = optEvent.get();

      // check if there's a running workflow
      final String wfState = event.getWorkflowState();
      if (wfState != null && WorkflowUtil.isActive(wfState)) {
        eventsWithRunningWorkflow.add(eventId);
        continue;
      }

      // collect metadata
      EventCatalogUIAdapter eventCatalogUiAdapter = getIndexService().getCommonEventCatalogUIAdapter();
      DublinCoreMetadataCollection metadataCollection = eventCatalogUiAdapter.getRawFields(
            getCollectionQueryDisable());
      EventUtils.setEventMetadataValues(event, metadataCollection);
      collectedMetadata.add(metadataCollection);

      eventsMerged.add(eventId);
    }

    // no events found?
    if (collectedMetadata.isEmpty()) {
      JsonObject response = new JsonObject();
      response.add("notFound", collectionToJsonArray(eventsNotFound));
      response.add("runningWorkflow", collectionToJsonArray(eventsWithRunningWorkflow));
      return Response.status(Status.NOT_FOUND).type(MediaType.APPLICATION_JSON_TYPE).build();
    }

    // merge metadata of events
    DublinCoreMetadataCollection mergedMetadata;
    if (collectedMetadata.size() == 1) {
      mergedMetadata = collectedMetadata.get(0);
    }
    else {
      //use first metadata collection as base
      mergedMetadata = new DublinCoreMetadataCollection(collectedMetadata.get(0));
      collectedMetadata.remove(0);

      for (MetadataField field : mergedMetadata.getFields()) {
        for (DublinCoreMetadataCollection otherMetadataCollection : collectedMetadata) {
          MetadataField matchingField = otherMetadataCollection.getOutputFields().get(field.getOutputID());

          // check if fields have the same value
          if (!Objects.equals(field.getValue(), matchingField.getValue())) {
            field.setDifferentValues();
            break;
          }
        }
      }
    }

    JsonObject result = new JsonObject();
    result.add("metadata", MetadataJson.collectionToJson(mergedMetadata, true, false));
    result.add("notFound", collectionToJsonArray(eventsNotFound));
    result.add("runningWorkflow", collectionToJsonArray(eventsWithRunningWorkflow));
    result.add("merged", collectionToJsonArray(eventsMerged));

    return okJson(result);
  }

  @PUT
  @Path("bulk/update")
  @Operation(
      summary = "Update multiple events",
      description = "Update all of the given events at once"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "All events have been updated successfully."),
      @ApiResponse(responseCode = "400", description = "Could not parse update instructions."),
      @ApiResponse(
          responseCode = "500",
          description = "Field updating metadata or scheduling information. Some events may have been "
              + "updated. Details are available in the response body."
      ),
      @ApiResponse(
          responseCode = "404",
          description = "The events in the response body were not found. No events were updated."
      )
  })
  public Response bulkUpdate(
      @Parameter(description = "The list of groups with events and fields to update.", required = true)
      @FormParam("update") String updateJson
  ) {

    final BulkUpdateUtil.BulkUpdateInstructions instructions;
    try {
      instructions = new BulkUpdateUtil.BulkUpdateInstructions(updateJson);
    } catch (IllegalArgumentException e) {
      return badRequest("Cannot parse bulk update instructions");
    }

    final Map<String, String> metadataUpdateFailures = new HashMap<>();
    final Map<String, String> schedulingUpdateFailures = new HashMap<>();

    for (final BulkUpdateUtil.BulkUpdateInstructionGroup groupInstructions : instructions.getGroups()) {
      // Get all the events to edit
      final Map<String, Optional<Event>> events = groupInstructions.getEventIds().stream()
          .collect(Collectors.toMap(id -> id, id -> BulkUpdateUtil.getEvent(getIndexService(), getIndex(), id)));

      // Check for invalid (non-existing) event ids
      final Set<String> notFoundIds = events.entrySet().stream()
          .filter(e -> !e.getValue().isPresent())
          .map(Entry::getKey)
          .collect(Collectors.toSet());
      if (!notFoundIds.isEmpty()) {
        return notFoundJson(collectionToJsonArray(notFoundIds));
      }


      events.values().forEach(e -> e.ifPresent(event -> {

        JsonObject metadata = null;

        // Update the scheduling information
        try {
          if (groupInstructions.getScheduling() != null) {
            // Since we only have the start/end time, we have to add the correct date(s) for this event.
            final JsonObject scheduling = BulkUpdateUtil.addSchedulingDates(event, groupInstructions.getScheduling());
            updateEventScheduling(scheduling.toString(), event);
            // We have to update the non-technical metadata as well to keep them in sync with the technical ones.
            metadata = BulkUpdateUtil.toNonTechnicalMetadataJson(scheduling);
          }
        } catch (Exception exception) {
          schedulingUpdateFailures.put(event.getIdentifier(), exception.getMessage());
        }

        // Update the event metadata
        try {
          if (groupInstructions.getMetadata() != null || metadata != null) {
            metadata = BulkUpdateUtil.mergeMetadataFields(metadata, groupInstructions.getMetadata());
            getIndexService().updateAllEventMetadata(event.getIdentifier(),
                singletonArray(metadata).toString(), getIndex());
          }
        } catch (Exception exception) {
          metadataUpdateFailures.put(event.getIdentifier(), exception.getMessage());
        }
      }));
    }

    // Check if there were any errors updating the metadata or scheduling information
    if (!metadataUpdateFailures.isEmpty() || !schedulingUpdateFailures.isEmpty()) {
      JsonObject json = new JsonObject();
      json.add("metadataFailures", mapToJsonObject(metadataUpdateFailures));
      json.add("schedulingFailures", mapToJsonObject(schedulingUpdateFailures));
      return serverErrorJson(json);
    }
    return ok();
  }

  @POST
  @Path("bulk/conflicts")
  @Operation(
      summary = "Check a bulk update for scheduling conflicts",
      description = "Checks if the current bulk update scheduling settings are in a conflict with another event"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "No conflicting events found"),
      @ApiResponse(
          responseCode = "404",
          description = "The events in the response body were not found. No events were updated."
      ),
      @ApiResponse(responseCode = "409", description = "There is a conflict"),
      @ApiResponse(
          responseCode = "400",
          description = "Missing or invalid parameters"
      )
  })
  public Response getBulkConflicts(
      @Parameter(
          description = "The list of events and fields to update.",
          required = true
      )
      @FormParam("update") final String updateJson
  ) throws NotFoundException {
    final BulkUpdateUtil.BulkUpdateInstructions instructions;
    try {
      instructions = new BulkUpdateUtil.BulkUpdateInstructions(updateJson);
    } catch (IllegalArgumentException e) {
      return badRequest("Cannot parse bulk update instructions");
    }

    final Map<String, List<JsonObject>> conflicts = new HashMap<>();
    final List<Tuple3<String, Optional<Event>, JsonObject>> eventsWithSchedulingOpt = instructions.getGroups().stream()
        .flatMap(group -> group.getEventIds().stream().map(eventId -> Tuple3
            .tuple3(eventId, BulkUpdateUtil.getEvent(getIndexService(), getIndex(), eventId), group.getScheduling())))
        .collect(Collectors.toList());
    // Check for invalid (non-existing) event ids
    final Set<String> notFoundIds = eventsWithSchedulingOpt.stream().filter(e -> !e.getB().isPresent())
        .map(Tuple3::getA).collect(Collectors.toSet());
    if (!notFoundIds.isEmpty()) {
      return notFoundJson(collectionToJsonArray(notFoundIds));
    }
    final List<Tuple<Event, JsonObject>> eventsWithScheduling = eventsWithSchedulingOpt.stream()
        .map(e -> Tuple.tuple(e.getB().get(), e.getC())).collect(Collectors.toList());
    final Set<String> changedIds = eventsWithScheduling.stream().map(e -> e.getA().getIdentifier())
        .collect(Collectors.toSet());
    for (final Tuple<Event, JsonObject> eventWithGroup : eventsWithScheduling) {
      final Event event = eventWithGroup.getA();
      final JsonObject groupScheduling = eventWithGroup.getB();
      try {
        if (groupScheduling != null) {
          // Since we only have the start/end time, we have to add the correct date(s) for this event.
          final JsonObject scheduling = BulkUpdateUtil.addSchedulingDates(event, groupScheduling);
          final Date start = Date.from(Instant.parse(GsonUtil.getStringOrNull(scheduling, SCHEDULING_START_KEY)));
          final Date end = Date.from(Instant.parse(GsonUtil.getStringOrNull(scheduling, SCHEDULING_END_KEY)));
          final String agentId = Optional.ofNullable(GsonUtil.getStringOrNull(scheduling, SCHEDULING_AGENT_ID_KEY))
              .orElse(event.getAgentId());

          final List<JsonObject> currentConflicts = new ArrayList<>();

          // Check for conflicts between the events themselves
          eventsWithScheduling.stream()
              .filter(otherEvent -> !otherEvent.getA().getIdentifier().equals(event.getIdentifier()))
              .forEach(otherEvent -> {
                final JsonObject otherScheduling = BulkUpdateUtil.addSchedulingDates(otherEvent.getA(),
                    otherEvent.getB());
                final Date otherStart = Date.from(
                    Instant.parse(GsonUtil.getStringOrNull(otherScheduling, SCHEDULING_START_KEY)));
                final Date otherEnd = Date.from(
                    Instant.parse(GsonUtil.getStringOrNull(otherScheduling, SCHEDULING_END_KEY)));
                final String otherAgentId = Optional
                    .ofNullable(GsonUtil.getStringOrNull(otherScheduling, SCHEDULING_AGENT_ID_KEY))
                    .orElse(otherEvent.getA().getAgentId());
                if (!otherAgentId.equals(agentId)) {
                  // different agent -> no conflict
                  return;
                }
                if (Util.schedulingIntervalsOverlap(start, end, otherStart, otherEnd)) {
                  // conflict
                  currentConflicts.add(convertEventToConflictingObject(
                      DateTimeSupport.toUTC(otherStart.getTime()),
                      DateTimeSupport.toUTC(otherEnd.getTime()),
                      otherEvent.getA().getTitle()));
                }
              });

          // Check for conflicts with other events from the database
          final List<MediaPackage> conflicting = getSchedulerService().findConflictingEvents(agentId, start, end)
              .stream()
              .filter(mp -> !changedIds.contains(mp.getIdentifier().toString()))
              .collect(Collectors.toList());
          if (!conflicting.isEmpty()) {
            currentConflicts.addAll(convertToConflictObjects(event.getIdentifier(), conflicting));
          }
          conflicts.put(event.getIdentifier(), currentConflicts);
        }
      } catch (final SchedulerException | UnauthorizedException | SearchIndexException exception) {
        throw new RuntimeException(exception);
      }
    }

    if (!conflicts.isEmpty()) {
      JsonArray responseJson = new JsonArray();

      conflicts.forEach((eventId, conflictingEvents) -> {
        if (!conflictingEvents.isEmpty()) {
          JsonObject obj = new JsonObject();
          obj.addProperty("eventId", eventId);

          JsonArray conflictsArray = new JsonArray();
          for (JsonObject conflict : conflictingEvents) {
            conflictsArray.add(conflict);
          }

          obj.add("conflicts", conflictsArray);
          responseJson.add(obj);
        }
      });

      if (responseJson.size() > 0) {
        return conflictJson(responseJson);
      }
    }

    return noContent();
  }

  @PUT
  @Path("{eventId}/metadata")
  @Operation(
      summary = "Update the metadata of an event",
      description = "Update the passed metadata for the event with the given Id"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The metadata have been updated."),
      @ApiResponse(responseCode = "400", description = "Could not parse metadata."),
      @ApiResponse(responseCode = "404", description = "No event with this identifier was found.")
  })
  public Response updateEventMetadata(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String id,
      @Parameter(description = "The list of metadata to update", required = true)
      @FormParam("metadata") String metadataJSON
  ) throws Exception {
    Optional<Event> optEvent = getIndexService().getEvent(id, getIndex());
    if (optEvent.isEmpty()) {
      return notFound("Cannot find an event with id '%s'.", id);
    }

    try {
      MetadataList metadataList = getIndexService().updateAllEventMetadata(id, metadataJSON, getIndex());
      return okJson(MetadataJson.listToJson(metadataList, true, false));
    } catch (IllegalArgumentException e) {
      return badRequest(String.format("Event %s metadata can't be updated.: %s", id, e.getMessage()));
    }
  }

  @PUT
  @Path("events/metadata")
  @Operation(
      summary = "Update the metadata of multiple events",
      description = "Update the passed metadata for the events with the given ids"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "All events have been updated successfully."),
      @ApiResponse(
          responseCode = "500",
          description = "One or multiple errors occured while updating event metadata. "
              + "Some events may have been updated successfully. "
              + "Details are available in the response body."
      )
  })
  public Response updateEventsMetadata(
      @Parameter(description = "The ids of the events to update", required = true)
      @FormParam("eventIds") String eventIds,
      @Parameter(description = "The metadata fields to update", required = true)
      @FormParam("metadata") String metadata
  ) throws Exception {

    if (StringUtils.isBlank(eventIds)) {
      return badRequest("Event ids can't be empty");
    }

    List<String> ids;
    try {
      ids = toIdList(eventIds);
    } catch (JsonParseException | IllegalStateException | UnsupportedOperationException e) {
      logger.error("Unable to parse '{}'", eventIds, e);
      return badRequest("Unable to parse event ids");
    }

    // try to update each event
    Set<String> eventsNotFound = new HashSet<>();
    Set<String> eventsUpdated = new HashSet<>();
    Set<String> eventsUpdateFailure = new HashSet();

    for (String eventId : ids) {
      Optional<Event> optEvent = getIndexService().getEvent(eventId, getIndex());
      // not found?

      if (optEvent.isEmpty()) {
        eventsNotFound.add(eventId);
        continue;
      }

      // update
      try {
        getIndexService().updateAllEventMetadata(eventId, metadata, getIndex());
        eventsUpdated.add(eventId);
      } catch (IllegalArgumentException e) {
        eventsUpdateFailure.add(eventId);
      }
    }

    // errors occurred?
    if (!eventsNotFound.isEmpty() || !eventsUpdateFailure.isEmpty()) {
      JsonObject errorJson = new JsonObject();

      errorJson.add("updateFailures", collectionToJsonArray(eventsUpdateFailure));
      errorJson.add("notFound", collectionToJsonArray(eventsNotFound));
      errorJson.add("updated", collectionToJsonArray(eventsUpdated));

      return serverErrorJson(errorJson);
    }

    return noContent();
  }

  @GET
  @Path("{eventId}/asset/assets.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the asset counts of an event",
      description = "Returns the number of assets from each types as JSON"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returns the number of assets from each types as JSON"),
      @ApiResponse(responseCode = "404", description = "No event with this identifier was found.")
  })
  public Response getAssetList(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String id
  ) throws Exception {
    Optional<Event> optEvent = getIndexService().getEvent(id, getIndex());
    if (optEvent.isEmpty()) {
      return notFound("Cannot find an event with id '%s'.", id);
    }
    MediaPackage mp;
    try {
      mp = getIndexService().getEventMediapackage(optEvent.get());
    } catch (IndexServiceException e) {
      if (e.getCause() instanceof NotFoundException) {
        return notFound("Cannot find data for event %s", id);
      } else if (e.getCause() instanceof UnauthorizedException) {
        return Response.status(Status.FORBIDDEN).entity("Not authorized to access " + id).build();
      }
      logger.error("Internal error when trying to access metadata for " + id, e);
      return serverError();
    }
    int attachments = mp.getAttachments().length;
    int catalogs = mp.getCatalogs().length;
    int media = mp.getTracks().length;
    int publications = mp.getPublications().length;

    JsonObject result = new JsonObject();
    result.addProperty("attachments", attachments);
    result.addProperty("catalogs", catalogs);
    result.addProperty("media", media);
    result.addProperty("publications", publications);

    return okJson(result);
  }

  @GET
  @Path("{eventId}/asset/attachment/attachments.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the attachments of an event",
      description = "Returns a list of attachments from the given event as JSON"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returns a list of attachments from the given event as JSON"),
      @ApiResponse(responseCode = "404", description = "No event with this identifier was found.")
  })
  public Response getAttachmentsList(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String id
  ) throws Exception {
    Optional<Event> optEvent = getIndexService().getEvent(id, getIndex());
    if (optEvent.isEmpty()) {
      return notFound("Cannot find an event with id '%s'.", id);
    }
    MediaPackage mp = getIndexService().getEventMediapackage(optEvent.get());
    return okJson(getEventMediaPackageElements(mp.getAttachments()));
  }

  @GET
  @Path("{eventId}/asset/attachment/{id}.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get an attachment of an event",
      description = "Returns the details of an attachment from the given event and attachment id as JSON"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "Returns the details of an attachment from the given event and attachment id as JSON"
      ),
      @ApiResponse(responseCode = "404", description = "No event or attachment with this identifier was found.")
  })
  public Response getAttachment(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String eventId,
      @Parameter(description = "The attachment id", required = true)
      @PathParam("id") String id
  ) throws NotFoundException, SearchIndexException, IndexServiceException {
    MediaPackage mp = getMediaPackageByEventId(eventId);

    Attachment attachment = mp.getAttachment(id);
    if (attachment == null) {
      return notFound("Cannot find an attachment with id '%s'.", id);
    }
    return okJson(attachmentToJSON(attachment));
  }

  @GET
  @Path("{eventId}/asset/catalog/catalogs.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the catalogs of an event",
      description = "Returns a list of catalogs from the given event as JSON"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returns a list of catalogs from the given event as JSON"),
      @ApiResponse(responseCode = "404", description = "No event with this identifier was found.")
  })
  public Response getCatalogList(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String id
  ) throws Exception {
    Optional<Event> optEvent = getIndexService().getEvent(id, getIndex());
    if (optEvent.isEmpty()) {
      return notFound("Cannot find an event with id '%s'.", id);
    }
    MediaPackage mp = getIndexService().getEventMediapackage(optEvent.get());
    return okJson(getEventMediaPackageElements(mp.getCatalogs()));
  }

  @GET
  @Path("{eventId}/asset/catalog/{id}.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get a catalog of an event",
      description = "Returns the details of a catalog from the given event and catalog id as JSON"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "Returns the details of a catalog from the given event and catalog id as JSON"
      ),
      @ApiResponse(responseCode = "404", description = "No event or catalog with this identifier was found.")
  })
  public Response getCatalog(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String eventId,
      @Parameter(description = "The catalog id", required = true)
      @PathParam("id") String id
  ) throws NotFoundException, SearchIndexException, IndexServiceException {
    MediaPackage mp = getMediaPackageByEventId(eventId);

    Catalog catalog = mp.getCatalog(id);
    if (catalog == null) {
      return notFound("Cannot find a catalog with id '%s'.", id);
    }
    return okJson(catalogToJSON(catalog));
  }

  @GET
  @Path("{eventId}/asset/media/media.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the media of an event",
      description = "Returns a list of media from the given event as JSON"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returns a list of media from the given event as JSON"),
      @ApiResponse(responseCode = "404", description = "No event with this identifier was found.")
  })
  public Response getMediaList(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String id
  ) throws Exception {
    Optional<Event> optEvent = getIndexService().getEvent(id, getIndex());
    if (optEvent.isEmpty()) {
      return notFound("Cannot find an event with id '%s'.", id);
    }
    MediaPackage mp = getIndexService().getEventMediapackage(optEvent.get());
    return okJson(getEventMediaPackageElements(mp.getTracks()));
  }

  @GET
  @Path("{eventId}/asset/media/{id}.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get a media track of an event",
      description = "Returns the details of a media from the given event and media id as JSON"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "Returns the media of a catalog from the given event and media id as JSON"
      ),
      @ApiResponse(responseCode = "404", description = "No event or media with this identifier was found.")
  })
  public Response getMedia(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String eventId,
      @Parameter(description = "The media id", required = true)
      @PathParam("id") String id
  ) throws NotFoundException, SearchIndexException, IndexServiceException {
    MediaPackage mp = getMediaPackageByEventId(eventId);

    Track track = mp.getTrack(id);
    if (track == null) {
      return notFound("Cannot find media with id '%s'.", id);
    }
    return okJson(trackToJSON(track));
  }

  @GET
  @Path("{eventId}/asset/publication/publications.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the publication assets of an event",
      description = "Returns a list of publications from the given event as JSON"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returns a list of publications from the given event as JSON"),
      @ApiResponse(responseCode = "404", description = "No event with this identifier was found.")
  })
  public Response getPublicationList(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String id
  ) throws Exception {
    Optional<Event> optEvent = getIndexService().getEvent(id, getIndex());
    if (optEvent.isEmpty()) {
      return notFound("Cannot find an event with id '%s'.", id);
    }
    MediaPackage mp = getIndexService().getEventMediapackage(optEvent.get());
    return okJson(getEventPublications(mp.getPublications()));
  }

  @GET
  @Path("{eventId}/asset/publication/{id}.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get a publication asset of an event",
      description = "Returns the details of a publication from the given event and publication id as JSON"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "Returns the publication of a catalog from the given event and publication id as JSON"
      ),
      @ApiResponse(responseCode = "404", description = "No event or publication with this identifier was found.")
  })
  public Response getPublication(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String eventId,
      @Parameter(description = "The publication id", required = true)
      @PathParam("id") String id
  ) throws NotFoundException, SearchIndexException, IndexServiceException {
    MediaPackage mp = getMediaPackageByEventId(eventId);

    Publication publication = null;
    for (Publication p : mp.getPublications()) {
      if (id.equals(p.getIdentifier())) {
        publication = p;
        break;
      }
    }

    if (publication == null) {
      return notFound("Cannot find publication with id '%s'.", id);
    }
    return okJson(publicationToJSON(publication));
  }

  @GET
  @Path("{eventId}/tobira/pages")
  @Operation(
      summary = "Get the Tobira pages of an event",
      description = "Returns the pages of a connected Tobira instance that contain the given event"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The Tobira pages containing the given event"),
      @ApiResponse(responseCode = "404", description = "Tobira doesn't know about the given event"),
      @ApiResponse(responseCode = "503", description = "Tobira is not configured (correctly)")
  })
  public Response getEventHostPages(
      @Parameter(description = "The event identifier", required = true)
      @PathParam("eventId") String eventId
  ) {
    var tobira = TobiraService.getTobira(getSecurityService().getOrganization().getId());
    if (!tobira.ready()) {
      return Response.status(Status.SERVICE_UNAVAILABLE)
              .entity("Tobira is not configured (correctly)")
              .build();
    }

    try {
      var eventData = tobira.getEventHostPages(eventId);
      if (eventData == null) {
        throw new WebApplicationException(NOT_FOUND);
      }
      eventData.addProperty("baseURL", tobira.getOrigin());
      return Response.ok(eventData.toString()).build();
    } catch (TobiraException e) {
      throw new WebApplicationException(e, Status.INTERNAL_SERVER_ERROR);
    }
  }

  @GET
  @Path("{eventId}/workflows.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the workflows of an event",
      description = "Returns all the data related to the workflows tab in the event details modal as JSON"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "Returns all the data related to the event workflows tab as JSON"
      ),
      @ApiResponse(responseCode = "404", description = "No event with this identifier was found.")
  })
  public Response getEventWorkflows(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String id
  ) throws UnauthorizedException, SearchIndexException, JobEndpointException {
    Optional<Event> optEvent = getIndexService().getEvent(id, getIndex());
    if (optEvent.isEmpty()) {
      return notFound("Cannot find an event with id '%s'.", id);
    }

    try {
      if (optEvent.get().getEventStatus().equals("EVENTS.EVENTS.STATUS.SCHEDULED")) {
        Map<String, String> workflowConfig = getSchedulerService().getWorkflowConfig(id);
        JsonObject configJson = new JsonObject();
        for (Map.Entry<String, String> entry : workflowConfig.entrySet()) {
          configJson.addProperty(entry.getKey(), safeString(entry.getValue()));
        }

        Map<String, String> agentConfiguration = getSchedulerService().getCaptureAgentConfiguration(id);
        JsonObject responseJson = new JsonObject();
        responseJson.addProperty("workflowId", agentConfiguration.getOrDefault(
            CaptureParameters.INGEST_WORKFLOW_DEFINITION, ""));
        responseJson.add("configuration", configJson);

        return okJson(responseJson);
      } else {
        List<WorkflowInstance> workflowInstances = getWorkflowService().getWorkflowInstancesByMediaPackage(id);
        JsonArray jsonArray = new JsonArray();

        for (WorkflowInstance instance : workflowInstances) {
          JsonObject instanceJson = new JsonObject();
          instanceJson.addProperty("id", instance.getId());
          instanceJson.addProperty("title", safeString(instance.getTitle()));
          instanceJson.addProperty("status", WORKFLOW_STATUS_TRANSLATION_PREFIX + instance.getState().toString());

          Date created = instance.getDateCreated();
          instanceJson.addProperty("submitted", created != null ? DateTimeSupport.toUTC(created.getTime()) : "");

          String submitter = instance.getCreatorName();
          instanceJson.addProperty("submitter", safeString(submitter));

          User user = submitter == null ? null : getUserDirectoryService().loadUser(submitter);
          String submitterName = null;
          String submitterEmail = null;
          if (user != null) {
            submitterName = user.getName();
            submitterEmail = user.getEmail();
          }
          instanceJson.addProperty("submitterName", safeString(submitterName));
          instanceJson.addProperty("submitterEmail", safeString(submitterEmail));

          jsonArray.add(instanceJson);
        }

        JsonObject result = new JsonObject();
        result.add("results", jsonArray);
        result.addProperty("count", workflowInstances.size());

        return okJson(result);
      }
    } catch (NotFoundException e) {
      return notFound("Cannot find workflows for event %s", id);
    } catch (SchedulerException e) {
      logger.error("Unable to get workflow data for event with id {}", id);
      throw new WebApplicationException(e, SC_INTERNAL_SERVER_ERROR);
    } catch (WorkflowDatabaseException e) {
      throw new JobEndpointException(String.format("Not able to get the list of job from the database: %s", e),
              e.getCause());
    }
  }

  @PUT
  @Path("{eventId}/workflows")
  @Operation(
      summary = "Update the workflow configuration of an event",
      description = "Update the workflow configuration for the scheduled event with the given id"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "Request executed succesfully"),
      @ApiResponse(responseCode = "404", description = "No event with this identifier was found.")
  })
  public Response updateEventWorkflow(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String id,
      @Parameter(description = "The workflow configuration as JSON", required = true)
      @FormParam("configuration") String configuration
  ) throws SearchIndexException, UnauthorizedException {
    Optional<Event> optEvent = getIndexService().getEvent(id, getIndex());
    if (optEvent.isEmpty()) {
      return notFound("Cannot find an event with id '%s'.", id);
    }

    if (optEvent.get().isScheduledEvent() && !optEvent.get().hasRecordingStarted()) {
      try {

        JsonObject configJSON;
        try {
          configJSON = GsonUtil.gson().fromJson(configuration, JsonObject.class);
        } catch (Exception e) {
          logger.warn("Unable to parse the workflow configuration {}", configuration);
          return badRequest();
        }

        Optional<Map<String, String>> caMetadataOpt = Optional.empty();
        Optional<Map<String, String>> workflowConfigOpt = Optional.empty();

        String workflowId = GsonUtil.getStringOrNull(configJSON, "id");
        Map<String, String> caMetadata = new HashMap<>(getSchedulerService().getCaptureAgentConfiguration(id));
        if (!workflowId.equals(caMetadata.get(CaptureParameters.INGEST_WORKFLOW_DEFINITION))) {
          caMetadata.put(CaptureParameters.INGEST_WORKFLOW_DEFINITION, workflowId);
          caMetadataOpt = Optional.of(caMetadata);
        }

        Map<String, String> workflowConfig = GsonUtil.toStringMap(configJSON.getAsJsonObject("configuration"));
        Map<String, String> oldWorkflowConfig = new HashMap<>(getSchedulerService().getWorkflowConfig(id));
        if (!oldWorkflowConfig.equals(workflowConfig)) {
          workflowConfigOpt = Optional.of(workflowConfig);
        }

        if (caMetadataOpt.isEmpty() && workflowConfigOpt.isEmpty()) {
          return Response.noContent().build();
        }

        checkAgentAccessForAgent(optEvent.get().getAgentId());

        getSchedulerService().updateEvent(id, Optional.empty(), Optional.empty(), Optional.empty(),
            Optional.empty(), Optional.empty(), workflowConfigOpt, caMetadataOpt);
        return Response.noContent().build();
      } catch (NotFoundException e) {
        return notFound("Cannot find event %s in scheduler service", id);
      } catch (SchedulerException e) {
        logger.error("Unable to update scheduling workflow data for event with id {}", id);
        throw new WebApplicationException(e, SC_INTERNAL_SERVER_ERROR);
      }
    } else {
      return badRequest(String.format("Event %s workflow can not be updated as the recording already started.", id));
    }
  }

  @GET
  @Path("{eventId}/workflows/{workflowId}")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get a workflow of an event",
      description = "Returns all the data related to the single workflow tab in the event details modal as JSON"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "Returns all the data related to the event single workflow tab as JSON"
      ),
      @ApiResponse(responseCode = "400", description = "Unable to parse workflowId"),
      @ApiResponse(responseCode = "404", description = "No event with this identifier was found.")
  })
  public Response getEventWorkflow(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String eventId,
      @Parameter(description = "The workflow id", required = true)
      @PathParam("workflowId") String workflowId
  ) throws SearchIndexException {
    Optional<Event> optEvent = getIndexService().getEvent(eventId, getIndex());
    if (optEvent.isEmpty()) {
      return notFound("Cannot find an event with id '%s'.", eventId);
    }

    long workflowInstanceId;
    try {
      workflowId = Strings.CS.remove(workflowId, ".json");
      workflowInstanceId = Long.parseLong(workflowId);
    } catch (Exception e) {
      logger.warn("Unable to parse workflow id {}", workflowId);
      return RestUtil.R.badRequest();
    }

    try {
      WorkflowInstance instance = getWorkflowService().getWorkflowById(workflowInstanceId);
      // Retrieve submission date with the workflow instance main job
      Date created = instance.getDateCreated();
      Date completed = instance.getDateCompleted();
      if (completed == null) {
        completed = new Date();
      }

      long executionTime = completed.getTime() - created.getTime();

      JsonObject configurationObj = new JsonObject();
      for (Entry<String, String> entry : instance.getConfigurations().entrySet()) {
        configurationObj.addProperty(entry.getKey(), safeString(entry.getValue()));
      }

      JsonObject json = new JsonObject();
      json.addProperty("status", WORKFLOW_STATUS_TRANSLATION_PREFIX + instance.getState());
      json.addProperty("description", safeString(instance.getDescription()));
      json.addProperty("executionTime", executionTime);
      json.addProperty("wiid", instance.getId());
      json.addProperty("title", safeString(instance.getTitle()));
      json.addProperty("wdid", safeString(instance.getTemplate()));
      if (!configurationObj.isEmpty()) {
        json.add("configuration", configurationObj);
      }
      json.addProperty("submittedAt", DateTimeSupport.toUTC(created.getTime()));
      json.addProperty("creator", safeString(instance.getCreatorName()));

      return okJson(json);

    } catch (NotFoundException e) {
      return notFound("Cannot find workflow  %s", workflowId);
    } catch (WorkflowDatabaseException e) {
      logger.error("Unable to get workflow {} of event {}", workflowId, eventId, e);
      return serverError();
    } catch (UnauthorizedException e) {
      return forbidden();
    }
  }

  @GET
  @Path("{eventId}/workflows/{workflowId}/operations.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the operations of an event workflow",
      description = "Returns all the data related to the workflow/operations tab in the event details modal as JSON"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "Returns all the data related to the event workflow/operations tab as JSON"
      ),
      @ApiResponse(responseCode = "400", description = "Unable to parse workflowId"),
      @ApiResponse(responseCode = "404", description = "No event with this identifier was found.")
  })
  public Response getEventOperations(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String eventId,
      @Parameter(description = "The workflow id", required = true)
      @PathParam("workflowId") String workflowId
  ) throws SearchIndexException {
    Optional<Event> optEvent = getIndexService().getEvent(eventId, getIndex());
    if (optEvent.isEmpty()) {
      return notFound("Cannot find an event with id '%s'.", eventId);
    }

    long workflowInstanceId;
    try {
      workflowInstanceId = Long.parseLong(workflowId);
    } catch (Exception e) {
      logger.warn("Unable to parse workflow id {}", workflowId);
      return RestUtil.R.badRequest();
    }

    try {
      WorkflowInstance instance = getWorkflowService().getWorkflowById(workflowInstanceId);
      List<WorkflowOperationInstance> operations = instance.getOperations();
      JsonArray operationsJsonArray = new JsonArray();

      for (WorkflowOperationInstance wflOp : operations) {
        JsonObject operationJson = new JsonObject();
        operationJson.addProperty("status", WORKFLOW_STATUS_TRANSLATION_PREFIX + wflOp.getState());
        operationJson.addProperty("title", safeString(wflOp.getTemplate()));
        operationJson.addProperty("description", safeString(wflOp.getDescription()));
        operationJson.addProperty("id", wflOp.getId());
        if (!wflOp.getConfigurationKeys().isEmpty()) {
          operationJson.add("configuration", collectionToJsonArray(wflOp.getConfigurationKeys()));
        }
        operationsJsonArray.add(operationJson);
      }

      return okJson(operationsJsonArray);
    } catch (NotFoundException e) {
      return notFound("Cannot find workflow %s", workflowId);
    } catch (WorkflowDatabaseException e) {
      logger.error("Unable to get workflow operations of event {} and workflow {}", eventId, workflowId, e);
      return serverError();
    } catch (UnauthorizedException e) {
      return forbidden();
    }
  }

  @GET
  @Path("{eventId}/workflows/{workflowId}/operations/{operationPosition}")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get an operation of an event workflow",
      description = "Returns all the data related to the workflow/operation tab in the event details modal as JSON"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "Returns all the data related to the event workflow/operation tab as JSON"
      ),
      @ApiResponse(responseCode = "400", description = "Unable to parse workflowId or operationPosition"),
      @ApiResponse(responseCode = "404", description = "No operation with these identifiers was found.")
  })
  public Response getEventOperation(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String eventId,
      @Parameter(description = "The workflow id", required = true)
      @PathParam("workflowId") String workflowId,
      @Parameter(description = "The operation position", required = true)
      @PathParam("operationPosition") Integer operationPosition
  ) throws SearchIndexException {
    Optional<Event> optEvent = getIndexService().getEvent(eventId, getIndex());
    if (optEvent.isEmpty()) {
      return notFound("Cannot find an event with id '%s'.", eventId);
    }

    long workflowInstanceId;
    try {
      workflowInstanceId = Long.parseLong(workflowId);
    } catch (Exception e) {
      logger.warn("Unable to parse workflow id {}", workflowId);
      return RestUtil.R.badRequest();
    }

    WorkflowInstance instance;
    try {
      instance = getWorkflowService().getWorkflowById(workflowInstanceId);
    } catch (NotFoundException e) {
      return notFound("Cannot find workflow %s", workflowId);
    } catch (WorkflowDatabaseException e) {
      logger.error("Unable to get workflow operation of event {} and workflow {} at position {}", eventId, workflowId,
          operationPosition, e);
      return serverError();
    } catch (UnauthorizedException e) {
      return forbidden();
    }

    List<WorkflowOperationInstance> operations = instance.getOperations();

    if (operationPosition < operations.size()) {
      WorkflowOperationInstance wflOp = operations.get(operationPosition);
      JsonObject json = new JsonObject();

      json.addProperty("retry_strategy", wflOp.getRetryStrategy() != null ? wflOp.getRetryStrategy().toString() : "");
      json.addProperty("execution_host", safeString(wflOp.getExecutionHost()));
      json.addProperty("failed_attempts", wflOp.getFailedAttempts());
      json.addProperty("max_attempts", wflOp.getMaxAttempts());
      json.addProperty("exception_handler_workflow", safeString(wflOp.getExceptionHandlingWorkflow()));
      json.addProperty("fail_on_error", wflOp.isFailOnError());
      json.addProperty("description", safeString(wflOp.getDescription()));
      json.addProperty("state", WORKFLOW_STATUS_TRANSLATION_PREFIX + wflOp.getState());
      json.addProperty("job", wflOp.getId());
      json.addProperty("name", safeString(wflOp.getTemplate()));
      json.addProperty("time_in_queue", wflOp.getTimeInQueue() != null ? wflOp.getTimeInQueue() : 0);
      json.addProperty("started", wflOp.getDateStarted() != null ? toUTC(wflOp.getDateStarted().getTime()) : "");
      json.addProperty("completed", wflOp.getDateCompleted() != null ? toUTC(wflOp.getDateCompleted().getTime()) : "");

      return okJson(json);
    }

    return notFound("Cannot find workflow operation of workflow %s at position %s", workflowId, operationPosition);
  }

  @GET
  @Path("{eventId}/workflows/{workflowId}/errors.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the errors of an event workflow",
      description = "Returns all the data related to the workflow/errors tab in the event details modal as JSON"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "Returns all the data related to the event workflow/errors tab as JSON"
      ),
      @ApiResponse(responseCode = "400", description = "Unable to parse workflowId"),
      @ApiResponse(responseCode = "404", description = "No event with this identifier was found.")
  })
  public Response getEventErrors(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String eventId,
      @Parameter(description = "The workflow id", required = true)
      @PathParam("workflowId") String workflowId,
      @Context HttpServletRequest req
  ) throws JobEndpointException, SearchIndexException {
    // the call to #getEvent should make sure that the calling user has access rights to the workflow
    // FIXME since there is no dependency between the event and the workflow (the fetched event is
    // simply ignored) an attacker can get access by using an event he owns and a workflow ID of
    // someone else.
    Optional<Event> eventOpt = getIndexService().getEvent(eventId, getIndex());
    if (eventOpt.isPresent()) {
      final long workflowIdLong;
      try {
        workflowIdLong = Long.parseLong(workflowId);
      } catch (Exception e) {
        logger.warn("Unable to parse workflow id {}", workflowId);
        return RestUtil.R.badRequest();
      }
      try {
        return okJson(getJobService().getIncidentsAsJSON(workflowIdLong, req.getLocale(), true));
      } catch (NotFoundException e) {
        return notFound("Cannot find the incident for the workflow %s", workflowId);
      }
    }
    return notFound("Cannot find an event with id '%s'.", eventId);
  }

  @GET
  @Path("{eventId}/workflows/{workflowId}/errors/{errorId}.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get an error of an event workflow",
      description = "Returns all the data related to the workflow/error tab in the event details modal as JSON"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "Returns all the data related to the event workflow/error tab as JSON"
      ),
      @ApiResponse(responseCode = "400", description = "Unable to parse workflowId"),
      @ApiResponse(responseCode = "404", description = "No event with this identifier was found.")
  })

  public Response getEventError(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String eventId,
      @Parameter(description = "The workflow id", required = true)
      @PathParam("workflowId") String workflowId,
      @Parameter(description = "The error id", required = true)
      @PathParam("errorId") String errorId,
      @Context HttpServletRequest req
  ) throws JobEndpointException, SearchIndexException {
    // the call to #getEvent should make sure that the calling user has access rights to the workflow
    // FIXME since there is no dependency between the event and the workflow (the fetched event is
    // simply ignored) an attacker can get access by using an event he owns and a workflow ID of
    // someone else.
    Optional<Event> eventOpt = getIndexService().getEvent(eventId, getIndex());
    if (eventOpt.isPresent()) {
      final long errorIdLong;
      try {
        errorIdLong = Long.parseLong(errorId);
      } catch (Exception e) {
        logger.warn("Unable to parse error id {}", errorId);
        return RestUtil.R.badRequest();
      }
      try {
        return okJson(getJobService().getIncidentAsJSON(errorIdLong, req.getLocale()));
      } catch (NotFoundException e) {
        return notFound("Cannot find the incident %s", errorId);
      }
    }
    return notFound("Cannot find an event with id '%s'.", eventId);
  }

  @GET
  @Path("{eventId}/access.json")
  @SuppressWarnings("unchecked")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the access information of an event",
      description = "Get the access information of an event"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "400",
          description = "The required form params were missing in the request."
      ),
      @ApiResponse(responseCode = "404", description = "If the event has not been found."),
      @ApiResponse(responseCode = "200", description = "The access information ")
  })
  public Response getEventAccessInformation(
      @Parameter(description = "The event identifier", required = true)
      @PathParam("eventId") String eventId
  ) throws Exception {
    Optional<Event> optEvent = getIndexService().getEvent(eventId, getIndex());
    if (optEvent.isEmpty()) {
      return notFound("Cannot find an event with id '%s'.", eventId);
    }

    // Add all available ACLs to the response
    JsonArray systemAclsJson = new JsonArray();
    List<ManagedAcl> acls = getAclService().getAcls();
    for (ManagedAcl acl : acls) {
      systemAclsJson.add(fromJettison(AccessInformationUtil.serializeManagedAcl(acl)));
    }

    AccessControlList activeAcl = new AccessControlList();
    try {
      if (optEvent.get().getAccessPolicy() != null) {
        activeAcl = AccessControlParser.parseAcl(optEvent.get().getAccessPolicy());
      }
    } catch (Exception e) {
      logger.error("Unable to parse access policy", e);
    }
    Optional<ManagedAcl> currentAcl = AccessInformationUtil.matchAclsLenient(acls, activeAcl,
            getAdminUIConfiguration().getMatchManagedAclRolePrefixes());

    JsonObject episodeAccessJson = new JsonObject();
    episodeAccessJson.addProperty("current_acl", currentAcl.isPresent() ? currentAcl.get().getId() : 0L);
    episodeAccessJson.add("acl", transformAccessControList(activeAcl, getUserDirectoryService()));
    episodeAccessJson.add("privileges", fromJettison(AccessInformationUtil.serializePrivilegesByRole(activeAcl)));
    if (StringUtils.isNotBlank(optEvent.get().getWorkflowState())
            && WorkflowUtil.isActive(optEvent.get().getWorkflowState())) {
      episodeAccessJson.addProperty("locked", true);
    }

    JsonObject jsonReturnObj = new JsonObject();
    jsonReturnObj.add("episode_access", episodeAccessJson);
    jsonReturnObj.add("system_acls", systemAclsJson);

    return Response.ok(jsonReturnObj.toString()).build();
  }

  // MH-12085 Add manually uploaded assets, multipart file upload has to be a POST
  @POST
  @Path("{eventId}/assets")
  @Consumes(MediaType.MULTIPART_FORM_DATA)
  @Operation(
      summary = "Update or create an asset of an event",
      description = "Update or create an asset for the eventId by the given metadata as JSON and files in the body"
  )
  @RequestBody(
      content = {
          @Content(
              mediaType = MediaType.MULTIPART_FORM_DATA,
              schema = @Schema(type = "object", requiredProperties = {"metadata"}),
              schemaProperties = {
                  @SchemaProperty(
                      name = "metadata",
                      schema = @Schema(
                          type = "string",
                          description = "The list of asset metadata"
                      )
                  )
              }
          )
      }
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The asset has been added."),
      @ApiResponse(responseCode = "400", description = "Could not add asset, problem with the metadata or files."),
      @ApiResponse(responseCode = "404", description = "No event with this identifier was found.")
  })
  public Response updateAssets(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") final String eventId,
      @Context HttpServletRequest request
  ) throws Exception {
    try {
      MediaPackage mp = getMediaPackageByEventId(eventId);
      String result = getIndexService().updateEventAssets(mp, request);
      return Response.status(Status.CREATED).entity(result).build();
    }  catch (NotFoundException e) {
      return notFound("Cannot find an event with id '%s'.", eventId);
    } catch (IllegalArgumentException | UnsupportedAssetException e) {
      return RestUtil.R.badRequest(e.getMessage());
    } catch (Exception e) {
      return RestUtil.R.serverError();
    }
  }

  @GET
  @Path("new/metadata")
  @Operation(
      summary = "Get the metadata for the new event form",
      description = "Returns all the data related to the metadata tab in the new event modal as JSON"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "Returns all the data related to the event metadata tab as JSON"
      )
  })
  public Response getNewMetadata() {
    MetadataList metadataList = new MetadataList();

    // Extended metadata
    List<EventCatalogUIAdapter> extendedCatalogUIAdapters = getIndexService().getExtendedEventCatalogUIAdapters();
    for (EventCatalogUIAdapter extendedCatalogUIAdapter : extendedCatalogUIAdapters) {
      metadataList.add(extendedCatalogUIAdapter, extendedCatalogUIAdapter.getRawFields());
    }

    // Common metadata
    // We do this after extended metadata because we want to overwrite any extended metadata adapters with the same
    // flavor instead of the other way around.
    EventCatalogUIAdapter commonCatalogUiAdapter = getIndexService().getCommonEventCatalogUIAdapter();
    DublinCoreMetadataCollection commonMetadata = commonCatalogUiAdapter.getRawFields(getCollectionQueryDisable());

    if (commonMetadata.getOutputFields().containsKey(DublinCore.PROPERTY_CREATED.getLocalName())) {
      commonMetadata.removeField(commonMetadata.getOutputFields().get(DublinCore.PROPERTY_CREATED.getLocalName()));
    }
    if (commonMetadata.getOutputFields().containsKey("duration")) {
      commonMetadata.removeField(commonMetadata.getOutputFields().get("duration"));
    }
    if (commonMetadata.getOutputFields().containsKey(DublinCore.PROPERTY_IDENTIFIER.getLocalName())) {
      commonMetadata.removeField(commonMetadata.getOutputFields().get(DublinCore.PROPERTY_IDENTIFIER.getLocalName()));
    }
    if (commonMetadata.getOutputFields().containsKey(DublinCore.PROPERTY_SOURCE.getLocalName())) {
      commonMetadata.removeField(commonMetadata.getOutputFields().get(DublinCore.PROPERTY_SOURCE.getLocalName()));
    }
    if (commonMetadata.getOutputFields().containsKey("startDate")) {
      commonMetadata.removeField(commonMetadata.getOutputFields().get("startDate"));
    }
    if (commonMetadata.getOutputFields().containsKey("startTime")) {
      commonMetadata.removeField(commonMetadata.getOutputFields().get("startTime"));
    }
    if (commonMetadata.getOutputFields().containsKey("location")) {
      commonMetadata.removeField(commonMetadata.getOutputFields().get("location"));
    }

    // Set publisher to user
    if (commonMetadata.getOutputFields().containsKey(DublinCore.PROPERTY_PUBLISHER.getLocalName())) {
      MetadataField publisher = commonMetadata.getOutputFields().get(DublinCore.PROPERTY_PUBLISHER.getLocalName());
      Map<String, String> users = new HashMap<>();
      if (publisher.getCollection() != null) {
        users = publisher.getCollection();
      }
      String loggedInUser = getSecurityService().getUser().getName();
      if (!users.containsKey(loggedInUser)) {
        users.put(loggedInUser, loggedInUser);
      }
      publisher.setValue(loggedInUser);
    }

    metadataList.add(commonCatalogUiAdapter, commonMetadata);

    // remove series with empty titles from the collection of the isPartOf field as these can't be converted to json
    removeSeriesWithNullTitlesFromFieldCollection(metadataList);

    return okJson(MetadataJson.listToJson(metadataList, true, false));
  }

  @GET
  @Path("new/processing")
  @Operation(
      summary = "Get the processing options for the new event form",
      description = "Returns all the data related to the processing tab in the new event modal as JSON"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "Returns all the data related to the event processing tab as JSON"
      )
  })
  public Response getNewProcessing(
      @Parameter(
          description = "A comma separated list of tags to filter the workflow definitions"
      )
      @QueryParam("tags") String tagsString
  ) {
    List<String> tags = RestUtil.splitCommaSeparatedParam(Optional.ofNullable(tagsString));

    JsonArray workflowsArray = new JsonArray();
    try {
      List<WorkflowDefinition> workflowsDefinitions = getWorkflowService().listAvailableWorkflowDefinitions();
      for (WorkflowDefinition wflDef : workflowsDefinitions) {
        if (wflDef.containsTag(tags)) {
          JsonObject wfJson = new JsonObject();
          wfJson.addProperty("id", wflDef.getId());
          wfJson.add("tags", arrayToJsonArray(wflDef.getTags()));
          wfJson.addProperty("title", safeString(wflDef.getTitle()));
          wfJson.addProperty("description", safeString(wflDef.getDescription()));
          wfJson.addProperty("displayOrder", wflDef.getDisplayOrder());
          wfJson.addProperty("configuration_panel", safeString(wflDef.getConfigurationPanel()));
          wfJson.addProperty("configuration_panel_json", safeString(wflDef.getConfigurationPanelJson()));

          workflowsArray.add(wfJson);
        }
      }
    } catch (WorkflowDatabaseException e) {
      logger.error("Unable to get available workflow definitions", e);
      return RestUtil.R.serverError();
    }

    JsonObject data = new JsonObject();
    data.add("workflows", workflowsArray);
    data.addProperty("default_workflow_id", defaultWorkflowDefinionId);

    return okJson(data);
  }

  @POST
  @Path("new/conflicts")
  @Operation(
      summary = "Check a new event for scheduling conflicts",
      description = "Checks if the current scheduler parameters are in a conflict with another event"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "No conflicting events found"),
      @ApiResponse(responseCode = "409", description = "There is a conflict"),
      @ApiResponse(
          responseCode = "400",
          description = "Missing or invalid parameters"
      )
  })
  public Response getNewConflicts(
      @Parameter(description = "The metadata as JSON", required = true)
      @FormParam("metadata") String metadata
  ) throws NotFoundException {
    if (StringUtils.isBlank(metadata)) {
      logger.warn("Metadata is not specified");
      return Response.status(Status.BAD_REQUEST).build();
    }

    JsonObject metadataJson;
    try {
      metadataJson = GsonUtil.gson().fromJson(metadata, JsonObject.class);
    } catch (Exception e) {
      logger.warn("Unable to parse metadata {}", metadata);
      return RestUtil.R.badRequest("Unable to parse metadata");
    }

    String device;
    String startDate;
    String endDate;
    try {
      device = GsonUtil.getStringOrNull(metadataJson, "device");
      startDate = GsonUtil.getStringOrNull(metadataJson, "start");
      endDate = GsonUtil.getStringOrNull(metadataJson, "end");
    } catch (Exception e) {
      logger.warn("Unable to parse metadata {}", metadata);
      return RestUtil.R.badRequest("Unable to parse metadata");
    }

    if (StringUtils.isBlank(device) || StringUtils.isBlank(startDate) || StringUtils.isBlank(endDate)) {
      logger.warn("Either device, start date or end date were not specified");
      return Response.status(Status.BAD_REQUEST).build();
    }

    Date start;
    try {
      start = new Date(DateTimeSupport.fromUTC(startDate));
    } catch (Exception e) {
      logger.warn("Unable to parse start date {}", startDate);
      return RestUtil.R.badRequest("Unable to parse start date");
    }

    Date end;
    try {
      end = new Date(DateTimeSupport.fromUTC(endDate));
    } catch (Exception e) {
      logger.warn("Unable to parse end date {}", endDate);
      return RestUtil.R.badRequest("Unable to parse end date");
    }

    String rruleString = GsonUtil.getStringOrNull(metadataJson, "rrule");

    RRule<ZonedDateTime> rrule = null;
    TimeZone timeZone = TimeZone.getDefault();
    String durationString = null;
    if (StringUtils.isNotEmpty(rruleString)) {
      try {
        rrule = new RRule<>(rruleString);
        rrule.validate();
      } catch (Exception e) {
        logger.warn("Unable to parse rrule {}: {}", rruleString, e.getMessage());
        return Response.status(Status.BAD_REQUEST).build();
      }

      durationString = GsonUtil.getStringOrNull(metadataJson, "duration");
      if (StringUtils.isBlank(durationString)) {
        logger.warn("If checking recurrence, must include duration.");
        return Response.status(Status.BAD_REQUEST).build();
      }

      Agent agent = getCaptureAgentStateService().getAgent(device);
      String timezone = agent.getConfiguration().getProperty("capture.device.timezone");
      if (StringUtils.isBlank(timezone)) {
        timezone = TimeZone.getDefault().getID();
        logger.warn("No 'capture.device.timezone' set on agent {}. The default server timezone {} will be used.",
                device, timezone);
      }
      timeZone = TimeZone.getTimeZone(timezone);
    }

    String eventId = GsonUtil.getStringOrNull(metadataJson, "id");

    try {
      List<MediaPackage> events = null;
      if (StringUtils.isNotEmpty(rruleString)) {
        events = getSchedulerService().findConflictingEvents(device, rrule, start, end, Long.parseLong(durationString),
                timeZone);
      } else {
        events = getSchedulerService().findConflictingEvents(device, start, end);
      }
      if (!events.isEmpty()) {
        final List<JsonObject> eventsJSON = convertToConflictObjects(eventId, events);
        if (!eventsJSON.isEmpty()) {
          JsonArray jsonArray = new JsonArray();
          for (JsonObject jsonObj : eventsJSON) {
            jsonArray.add(jsonObj);
          }
          return conflictJson(jsonArray);
        }
      }
      return Response.noContent().build();
    } catch (Exception e) {
      logger.error("Unable to find conflicting events for {}, {}, {}",
              device, startDate, endDate, e);
      return RestUtil.R.serverError();
    }
  }

  private List<JsonObject> convertToConflictObjects(final String eventId, final List<MediaPackage> events)
          throws SearchIndexException {
    final List<JsonObject> eventsJSON = new ArrayList<>();
    final Organization organization = getSecurityService().getOrganization();
    final User user = SecurityUtil.createSystemUser(systemUserName, organization);

    SecurityUtil.runAs(getSecurityService(), organization, user, () -> {
      try {
        for (final MediaPackage event : events) {
          final Optional<Event> eventOpt = getIndexService().getEvent(event.getIdentifier().toString(), getIndex());
          if (eventOpt.isPresent()) {
            final Event e = eventOpt.get();
            if (StringUtils.isNotEmpty(eventId) && eventId.equals(e.getIdentifier())) {
              continue;
            }
            eventsJSON.add(convertEventToConflictingObject(e.getTechnicalStartTime(), e.getTechnicalEndTime(),
                e.getTitle()));
          } else {
            logger.warn("Index out of sync! Conflicting event catalog {} not found on event index!",
                event.getIdentifier().toString());
          }
        }
      } catch (Exception e) {
        logger.error("Failed to get conflicting events", e);
      }
    });

    return eventsJSON;
  }

  private JsonObject convertEventToConflictingObject(final String start, final String end, final String title) {
    JsonObject json = new JsonObject();
    json.addProperty("start", start);
    json.addProperty("end", end);
    json.addProperty("title", title);
    return json;
  }

  @POST
  @Path("/new")
  @Consumes(MediaType.MULTIPART_FORM_DATA)
  @Operation(
      summary = "Create a new event",
      description = "Creates a new event by the given metadata as JSON and the files in the body"
  )
  @RequestBody(
      content = {
          @Content(
              mediaType = MediaType.MULTIPART_FORM_DATA,
              schema = @Schema(type = "object", requiredProperties = {"metadata"}),
              schemaProperties = {
                  @SchemaProperty(
                      name = "metadata",
                      schema = @Schema(
                          type = "string",
                          description = "The metadata as JSON"
                      )
                  )
              }
          )
      }
  )
  @ApiResponses({
      @ApiResponse(responseCode = "201", description = "Event sucessfully added"),
      @ApiResponse(responseCode = "400", description = "If the metadata is not set or couldn't be parsed")
  })
  public Response createNewEvent(
      @Context HttpServletRequest request
  ) {
    try {
      String result = getIndexService().createEvent(request);
      if (StringUtils.isEmpty(result)) {
        return RestUtil.R.badRequest("The date range provided did not include any events");
      }
      return Response.status(Status.CREATED).entity(result).build();
    } catch (IllegalArgumentException | UnsupportedAssetException e) {
      return RestUtil.R.badRequest(e.getMessage());
    } catch (Exception e) {
      return RestUtil.R.serverError();
    }
  }

  @GET
  @Path("events.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get events",
      description = "Returns all the events as JSON"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returns all events as JSON")
  })
  public Response getEvents(
      @QueryParam("id") String id,
      @QueryParam("commentReason") String reasonFilter,
      @QueryParam("commentResolution") String resolutionFilter,
      @Parameter(
          description = "The filter used for the query. They "
              + "should be formated like that: 'filter1:value1,filter2:value2'"
      )
      @QueryParam("filter") String filter,
      @Parameter(
          description = "The order instructions used to sort the query result. Must be "
              + "in the form '<field name>:(ASC|DESC)'"
      )
      @QueryParam("sort") String sort,
      @Parameter(description = "The page number.")
      @QueryParam("offset") Integer offset,
      @Parameter(description = "The maximum number of items to return per page.")
      @QueryParam("limit") Integer limit,
      @Parameter(description = "If comments should be fetched")
      @QueryParam("getComments") Boolean getComments
  ) {

    Optional<Integer> optLimit = Optional.ofNullable(limit);
    Optional<Integer> optOffset = Optional.ofNullable(offset);
    Optional<String> optSort = Optional.ofNullable(trimToNull(sort));
    Optional<Boolean> optGetComments = Optional.ofNullable(getComments);
    List<JsonObject> eventsList = new ArrayList<>();
    final Organization organization = getSecurityService().getOrganization();
    final User user = getSecurityService().getUser();
    if (organization == null || user == null) {
      return Response.status(SC_SERVICE_UNAVAILABLE).build();
    }
    EventSearchQuery query = new EventSearchQuery(organization.getId(), user);

    // If the limit is set to 0, this is not taken into account
    if (optLimit.isPresent() && limit == 0) {
      optLimit = Optional.empty();
    }

    Map<String, String> filters = RestUtils.parseFilter(filter);
    for (String name : filters.keySet()) {
      if (EventListQuery.FILTER_PRESENTERS_BIBLIOGRAPHIC_NAME.equals(name)) {
        query.withPresenter(filters.get(name));
      }
      if (EventListQuery.FILTER_PRESENTERS_TECHNICAL_NAME.equals(name)) {
        query.withTechnicalPresenters(filters.get(name));
      }
      if (EventListQuery.FILTER_CONTRIBUTORS_NAME.equals(name)) {
        query.withContributor(filters.get(name));
      }
      if (EventListQuery.FILTER_LOCATION_NAME.equals(name)) {
        query.withLocation(filters.get(name));
      }
      if (EventListQuery.FILTER_LANGUAGE_NAME.equals(name)) {
        query.withLanguage(filters.get(name));
      }
      if (EventListQuery.FILTER_AGENT_NAME.equals(name)) {
        query.withAgentId(filters.get(name));
      }
      if (EventListQuery.FILTER_TEXT_NAME.equals(name)) {
        query.withText(filters.get(name));
      }
      if (EventListQuery.FILTER_SERIES_NAME.equals(name)) {
        query.withSeriesId(filters.get(name));
      }
      if (EventListQuery.FILTER_STATUS_NAME.equals(name)) {
        query.withEventStatus(filters.get(name));
      }
      if (EventListQuery.FILTER_PUBLISHER_NAME.equals(name)) {
        query.withPublisher(filters.get(name));
      }
      if (EventListQuery.FILTER_COMMENTS_NAME.equals(name)) {
        switch (Comments.valueOf(filters.get(name))) {
          case NONE:
            query.withComments(false);
            break;
          case OPEN:
            query.withOpenComments(true);
            break;
          case RESOLVED:
            query.withComments(true);
            query.withOpenComments(false);
            break;
          default:
            logger.info("Unknown comment {}", filters.get(name));
            return Response.status(SC_BAD_REQUEST).build();
        }
      }
      if (EventListQuery.FILTER_IS_PUBLISHED_NAME.equals(name)) {
        if (filters.containsKey(name)) {
          switch (IsPublished.valueOf(filters.get(name))) {
            case YES:
              query.withIsPublished(true);
              break;
            case NO:
              query.withIsPublished(false);
              break;
            default:
              break;
          }
        } else {
          logger.info("Query for invalid published status: {}", filters.get(name));
          return Response.status(SC_BAD_REQUEST).build();
        }
      }
      if (EventListQuery.FILTER_READ_ACCESS_NAME.equals(name)) {
        query.withAccessControlEntry(filters.get(name), Permissions.Action.READ);
      } else if (EventListQuery.FILTER_WRITE_ACCESS_NAME.equals(name)) {
        query.withAccessControlEntry(filters.get(name), Permissions.Action.WRITE);
      }
      if (EventListQuery.FILTER_NEEDS_CUTTING_NAME.equals(name)) {
        if (filters.containsKey(name)) {
          switch (EventsListProvider.NeedsCutting.valueOf(filters.get(name))) {
            case YES:
              query.withNeedsCutting(true);
              break;
            case NO:
              query.withNeedsCutting(false);
              break;
            default:
              break;
          }
        } else {
          logger.info("Query for invalid needs cutting status: {}", filters.get(name));
          return Response.status(SC_BAD_REQUEST).build();
        }
      }

      if (EventListQuery.FILTER_STARTDATE_NAME.equals(name)) {
        try {
          Tuple<Date, Date> fromAndToCreationRange = RestUtils.getFromAndToDateRange(filters.get(name));
          query.withStartFrom(fromAndToCreationRange.getA());
          query.withStartTo(fromAndToCreationRange.getB());
        } catch (IllegalArgumentException e) {
          return RestUtil.R.badRequest(e.getMessage());
        }
      }
    }

    if (optSort.isPresent()) {
      ArrayList<SortCriterion> sortCriteria = RestUtils.parseSortQueryParameter(optSort.get());
      for (SortCriterion criterion : sortCriteria) {
        switch (criterion.getFieldName()) {
          case EventIndexSchema.UID:
            query.sortByUID(criterion.getOrder());
            break;
          case EventIndexSchema.TITLE:
            query.sortByTitle(criterion.getOrder());
            break;
          case EventIndexSchema.PRESENTER:
            query.sortByPresenter(criterion.getOrder());
            break;
          case EventIndexSchema.TECHNICAL_START:
          case "technical_date":
            query.sortByTechnicalStartDate(criterion.getOrder());
            break;
          case EventIndexSchema.TECHNICAL_END:
            query.sortByTechnicalEndDate(criterion.getOrder());
            break;
          case EventIndexSchema.PUBLICATION:
            query.sortByPublicationIgnoringInternal(criterion.getOrder());
            break;
          case EventIndexSchema.START_DATE:
          case "date":
            query.sortByStartDate(criterion.getOrder());
            break;
          case EventIndexSchema.END_DATE:
            query.sortByEndDate(criterion.getOrder());
            break;
          case EventIndexSchema.SERIES_NAME:
            query.sortBySeriesName(criterion.getOrder());
            break;
          case EventIndexSchema.LOCATION:
            query.sortByLocation(criterion.getOrder());
            break;
          case EventIndexSchema.EVENT_STATUS:
            query.sortByEventStatus(criterion.getOrder());
            break;
          default:
            final String msg = String.format("Unknown sort criteria field %s", criterion.getFieldName());
            logger.debug(msg);
            return RestUtil.R.badRequest(msg);
        }
      }
    }

    // We search for write actions
    if (getOnlyEventsWithWriteAccessEventsTab()) {
      query.withoutActions();
      query.withAction(Permissions.Action.WRITE);
      query.withAction(Permissions.Action.READ);
    }

    if (optLimit.isPresent()) {
      query.withLimit(optLimit.get());
    }
    if (optOffset.isPresent()) {
      query.withOffset(offset);
    }
    // TODO: Add other filters to the query

    SearchResult<Event> results = null;
    try {
      results = getIndex().getByQuery(query);
    } catch (SearchIndexException e) {
      if (e.isBadRequest()) {
        logger.warn("The admin UI Search Index rejected the query for the events list: {}", e.getMessage());
        return RestUtil.R.badRequest(e.getMessage());
      }
      logger.error("The admin UI Search Index was not able to get the events list:", e);
      return RestUtil.R.serverError();
    }

    // If the results list if empty, we return already a response.
    if (results.getPageSize() == 0) {
      logger.debug("No events match the given filters.");
      return okJsonList(eventsList, Optional.ofNullable(offset).orElse(0), Optional.ofNullable(limit).orElse(0), 0);
    }

    Map<String, String> languages;
    try {
      languages = getListProvidersService().getList("LANGUAGES", new DefaultResourceListQuery(), false);
    } catch (ListProviderException e) {
      logger.info("Could not get languages from listprovider");
      throw new WebApplicationException(e);
    }

    for (SearchResultItem<Event> item : results.getItems()) {
      Event source = item.getSource();
      source.updatePreview(getAdminUIConfiguration().getPreviewSubtype());
      List<EventComment> comments = null;
      if (optGetComments.isPresent() && optGetComments.get()) {
        try {
          comments = getEventCommentService().getComments(source.getIdentifier());
        } catch (EventCommentException e) {
          logger.error("Unable to get comments from event {}", source.getIdentifier(), e);
          throw new WebApplicationException(e);
        }
      }
      eventsList.add(eventToJSON(source, Optional.ofNullable(comments), Optional.ofNullable(languages)));
    }

    return okJsonList(eventsList, Optional.ofNullable(offset).orElse(0), Optional.ofNullable(limit).orElse(0),
        results.getHitCount());
  }

  // --

  private MediaPackage getMediaPackageByEventId(String eventId)
          throws SearchIndexException, NotFoundException, IndexServiceException {
    Optional<Event> optEvent = getIndexService().getEvent(eventId, getIndex());
    if (optEvent.isEmpty()) {
      throw new NotFoundException(format("Cannot find an event with id '%s'.", eventId));
    }
    return getIndexService().getEventMediapackage(optEvent.get());
  }

  private URI getCommentUrl(String eventId, long commentId) {
    return UrlSupport.uri(serverUrl, eventId, "comment", Long.toString(commentId));
  }


  private JsonObject eventToJSON(Event event, Optional<List<EventComment>> comments,
      Optional<Map<String, String>> languages) {
    JsonObject json = new JsonObject();

    json.addProperty("id", event.getIdentifier());
    json.addProperty("title", event.getTitle() != null ? event.getTitle() : "");
    json.addProperty("source", event.getSource() != null ? event.getSource() : "");
    json.add("presenters", collectionToJsonArray(event.getPresenters()));

    if (StringUtils.isNotBlank(event.getSeriesId())) {
      JsonObject seriesObj = new JsonObject();
      seriesObj.addProperty("id", event.getSeriesId() != null ? event.getSeriesId() : "");
      seriesObj.addProperty("title", event.getSeriesName() != null ? event.getSeriesName() : "");
      json.add("series", seriesObj);
    }

    json.addProperty("location", safeString(event.getLocation()));
    json.addProperty("start_date", safeString(event.getRecordingStartDate()));
    json.addProperty("end_date", safeString(event.getRecordingEndDate()));
    json.addProperty("managedAcl", safeString(event.getManagedAcl()));
    json.addProperty("workflow_state", safeString(event.getWorkflowState()));
    json.addProperty("event_status", event.getEventStatus());
    json.addProperty("displayable_status", event.getDisplayableStatus(getWorkflowService().getWorkflowStateMappings()));
    json.addProperty("source", getIndexService().getEventSource(event).toString());
    json.addProperty("has_comments", event.hasComments());
    json.addProperty("has_open_comments", event.hasOpenComments());
    json.addProperty("needs_cutting", event.needsCutting());
    json.addProperty("has_preview", event.hasPreview());
    json.addProperty("agent_id", safeString(event.getAgentId()));
    json.addProperty("technical_start", safeString(event.getTechnicalStartTime()));
    json.addProperty("technical_end", safeString(event.getTechnicalEndTime()));
    json.addProperty("language", safeString(event.getLanguage()));
    json.addProperty("language_translation_key", languages.isPresent()
        ? safeString(languages.get().get(event.getLanguage())) : "");
    json.add("technical_presenters", collectionToJsonArray(event.getTechnicalPresenters()));
    json.add("publications", collectionToJsonArray(eventPublicationsToJson(event)));
    if (comments.isPresent()) {
      json.add("comments", collectionToJsonArray(eventCommentsToJson(comments.get())));
    }

    return json;
  }



  private void mergeJsonObjects(JsonObject target, JsonObject source) {
    for (String key : source.keySet()) {
      target.add(key, source.get(key));
    }
  }

  private JsonObject attachmentToJSON(Attachment attachment) {
    JsonObject json = new JsonObject();
    mergeJsonObjects(json, getEventMediaPackageElementFields(attachment));
    mergeJsonObjects(json, getCommonElementFields(attachment));
    return json;
  }

  private JsonObject catalogToJSON(Catalog catalog) {
    JsonObject json = new JsonObject();
    mergeJsonObjects(json, getEventMediaPackageElementFields(catalog));
    mergeJsonObjects(json, getCommonElementFields(catalog));
    return json;
  }

  private JsonObject trackToJSON(Track track) {
    JsonObject json = new JsonObject();
    mergeJsonObjects(json, getEventMediaPackageElementFields(track));
    mergeJsonObjects(json, getCommonElementFields(track));
    json.addProperty("duration", track.getDuration());
    json.addProperty("has_audio", track.hasAudio());
    json.addProperty("has_video", track.hasVideo());
    json.addProperty("has_subtitle", track.hasSubtitle());
    json.add("streams", streamsToJSON(track.getStreams()));
    return json;
  }

  private JsonObject streamsToJSON(org.opencastproject.mediapackage.Stream[] streams) {
    JsonArray audioArray = new JsonArray();
    JsonArray videoArray = new JsonArray();
    JsonArray subtitleArray = new JsonArray();

    for (org.opencastproject.mediapackage.Stream stream : streams) {
      if (stream instanceof AudioStreamImpl) {
        AudioStream audioStream = (AudioStream) stream;
        JsonObject audioJson = new JsonObject();
        audioJson.addProperty("id", safeString(audioStream.getIdentifier()));
        audioJson.addProperty("type", safeString(audioStream.getFormat()));
        audioJson.addProperty("channels", safeString(audioStream.getChannels()));
        audioJson.addProperty("bitrate", audioStream.getBitRate());
        audioJson.addProperty("bitdepth", safeString(audioStream.getBitDepth()));
        audioJson.addProperty("samplingrate", safeString(audioStream.getSamplingRate()));
        audioJson.addProperty("framecount", safeString(audioStream.getFrameCount()));
        audioJson.addProperty("peakleveldb", safeString(audioStream.getPkLevDb()));
        audioJson.addProperty("rmsleveldb", safeString(audioStream.getRmsLevDb()));
        audioJson.addProperty("rmspeakdb", safeString(audioStream.getRmsPkDb()));
        audioArray.add(audioJson);

      } else if (stream instanceof VideoStreamImpl) {
        VideoStream videoStream = (VideoStream) stream;
        JsonObject videoJson = new JsonObject();
        videoJson.addProperty("id", safeString(videoStream.getIdentifier()));
        videoJson.addProperty("type", safeString(videoStream.getFormat()));
        videoJson.addProperty("bitrate", videoStream.getBitRate());
        videoJson.addProperty("framerate", safeString(videoStream.getFrameRate()));
        videoJson.addProperty("resolution", safeString(videoStream.getFrameWidth() + "x"
            + videoStream.getFrameHeight()));
        videoJson.addProperty("framecount", safeString(videoStream.getFrameCount()));
        videoJson.addProperty("scantype", safeString(videoStream.getScanType()));
        videoJson.addProperty("scanorder", safeString(videoStream.getScanOrder()));
        videoArray.add(videoJson);

      } else if (stream instanceof SubtitleStreamImpl) {
        SubtitleStreamImpl subtitleStream = (SubtitleStreamImpl) stream;
        JsonObject subtitleJson = new JsonObject();
        subtitleJson.addProperty("id", safeString(subtitleStream.getIdentifier()));
        subtitleJson.addProperty("type", safeString(subtitleStream.getFormat()));
        subtitleArray.add(subtitleJson);

      } else {
        throw new IllegalArgumentException("Stream must be either audio, video, or subtitle");
      }
    }

    JsonObject result = new JsonObject();
    result.add("audio", audioArray);
    result.add("video", videoArray);
    result.add("subtitle", subtitleArray);
    return result;
  }

  private JsonObject publicationToJSON(Publication publication) {
    JsonObject json = new JsonObject();

    json.addProperty("id", safeString(publication.getIdentifier()));
    json.addProperty("channel", safeString(publication.getChannel()));
    json.addProperty("mimetype", safeString(publication.getMimeType()));
    json.add("tags", arrayToJsonArray(publication.getTags()));
    URI uri = signUrl(publication.getURI());
    json.addProperty("url", safeString(uri));

    JsonObject commonFields = getCommonElementFields(publication);
    for (String key : commonFields.keySet()) {
      json.add(key, commonFields.get(key));
    }

    return json;
  }

  private JsonObject getCommonElementFields(MediaPackageElement element) {
    JsonObject fields = new JsonObject();

    fields.addProperty("size", element.getSize());
    fields.addProperty("checksum", element.getChecksum() != null ? element.getChecksum().getValue() : "");
    fields.addProperty("reference", element.getReference() != null ? element.getReference().getIdentifier() : "");

    return fields;
  }

  /**
   * Render an array of {@link Publication}s into a list of JSON values.
   *
   * @param publications
   *          The elements to pull the data from to create the {@link JsonArray}
   * @return {@link JsonArray} that represent the {@link Publication}
   */
  private JsonArray getEventPublications(Publication[] publications) {
    JsonArray publicationJsonArray = new JsonArray();

    for (Publication publication : publications) {
      JsonObject pubJson = new JsonObject();

      pubJson.addProperty("id", safeString(publication.getIdentifier()));
      pubJson.addProperty("channel", safeString(publication.getChannel()));
      pubJson.addProperty("mimetype", safeString(publication.getMimeType()));
      pubJson.add("tags", arrayToJsonArray(publication.getTags()));
      pubJson.addProperty("url",  safeString(signUrl(publication.getURI())));

      publicationJsonArray.add(pubJson);
    }

    return publicationJsonArray;
  }

  private URI signUrl(URI url) {
    if (url == null) {
      return null;
    }
    if (getUrlSigningService().accepts(url.toString())) {
      try {
        String clientIP = null;
        if (signWithClientIP()) {
          clientIP = getSecurityService().getUserIP();
        }
        return URI.create(getUrlSigningService().sign(url.toString(), getUrlSigningExpireDuration(), null, clientIP));
      } catch (UrlSigningException e) {
        logger.warn("Unable to sign url '{}'", url, e);
      }
    }
    return url;
  }

  /**
   * Render an array of {@link MediaPackageElement}s into a list of JSON values.
   *
   * @param elements
   *          The elements to pull the data from to create the {@link JsonArray}
   * @return {@link JsonArray} that represent the {@link MediaPackageElement}
   */
  private JsonArray getEventMediaPackageElements(MediaPackageElement[] elements) {
    JsonArray elementJsonArray = new JsonArray();
    for (MediaPackageElement element : elements) {
      JsonObject elementJson = getEventMediaPackageElementFields(element);
      elementJsonArray.add(elementJson);
    }
    return elementJsonArray;
  }

  private JsonObject getEventMediaPackageElementFields(MediaPackageElement element) {
    JsonObject json = new JsonObject();

    json.addProperty("id", safeString(element.getIdentifier()));
    json.addProperty("type", safeString(element.getFlavor()));
    json.addProperty("mimetype", safeString(element.getMimeType()));
    json.add("tags", arrayToJsonArray(element.getTags()));
    json.addProperty("url", safeString(signUrl(element.getURI())));

    return json;
  }

  private final Function<Publication, JsonObject> publicationToJson = publication -> {
    String channelName = EventUtils.PUBLICATION_CHANNELS.get(publication.getChannel());
    if (channelName == null) {
      channelName = "EVENTS.EVENTS.DETAILS.PUBLICATIONS.CUSTOM";
    }
    String url = publication.getURI() == null ? "" : signUrl(publication.getURI()).toString();

    JsonObject json = new JsonObject();
    json.addProperty("id", publication.getChannel());
    json.addProperty("name", channelName);
    json.addProperty("url", url);

    return json;
  };

  private JsonObject technicalMetadataToJson(TechnicalMetadata technicalMetadata) {
    JsonObject json = new JsonObject();

    json.addProperty("agentId", technicalMetadata.getAgentId() != null ? technicalMetadata.getAgentId() : "");
    if (technicalMetadata.getCaptureAgentConfiguration() != null) {
      json.add("agentConfiguration", mapToJsonObject(technicalMetadata.getCaptureAgentConfiguration()));
    } else {
      json.add("agentConfiguration", JsonNull.INSTANCE);
    }
    if (technicalMetadata.getStartDate() != null) {
      String startUtc = DateTimeSupport.toUTC(technicalMetadata.getStartDate().getTime());
      json.addProperty("start", startUtc);
    } else {
      json.addProperty("start", "");
    }
    if (technicalMetadata.getEndDate() != null) {
      String endUtc = DateTimeSupport.toUTC(technicalMetadata.getEndDate().getTime());
      json.addProperty("end", endUtc);
    } else {
      json.addProperty("end", "");
    }
    String eventId = technicalMetadata.getEventId();
    json.addProperty("eventId", safeString(eventId));
    json.add("presenters", collectionToJsonArray(technicalMetadata.getPresenters()));
    Optional<Recording> optRecording = technicalMetadata.getRecording();
    if (optRecording.isPresent()) {
      json.add("recording", recordingToJson(optRecording.get()));
    }

    return json;
  }

  public static JsonObject recordingToJson(Recording recording) {
    JsonObject json = new JsonObject();

    json.addProperty("id", safeString(recording.getID()));
    json.addProperty("lastCheckInTime", recording.getLastCheckinTime() != null ? recording.getLastCheckinTime() : 0L);
    json.addProperty("lastCheckInTimeUTC", recording.getLastCheckinTime() != null
        ? toUTC(recording.getLastCheckinTime()) : "");
    json.addProperty("state", safeString(recording.getState()));

    return json;
  }

  @PUT
  @Path("{eventId}/workflows/{workflowId}/action/{action}")
  @Operation(
      summary = "Perform an action on an event workflow",
      description = "Performs the given action for the given workflow."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Workflow resumed."),
      @ApiResponse(responseCode = "404", description = "Event or workflow instance not found."),
      @ApiResponse(responseCode = "400", description = "Invalid action entered."),
      @ApiResponse(
          responseCode = "401",
          description = "You do not have permission to perform the action. Maybe you need to authenticate."
      ),
      @ApiResponse(responseCode = "500", description = "An exception occurred.")
  })
  public Response workflowAction(
      @Parameter(description = "The id of the media package", required = true)
      @PathParam("eventId") String id,
      @Parameter(description = "The id of the workflow", required = true)
      @PathParam("workflowId") long wfId,
      @Parameter(description = "The action to take: STOP, RETRY or NONE (abort processing)", required = true)
      @PathParam("action") String action
  ) {
    if (StringUtils.isEmpty(id) || StringUtils.isEmpty(action)) {
      return badRequest();
    }

    try {
      final Optional<Event> optEvent = getIndexService().getEvent(id, getIndex());
      if (optEvent.isEmpty()) {
        return notFound("Cannot find an event with id '%s'.", id);
      }

      final WorkflowInstance wfInstance = getWorkflowService().getWorkflowById(wfId);
      if (!wfInstance.getMediaPackage().getIdentifier().toString().equals(id)) {
        return badRequest(String.format("Workflow %s is not associated to event %s", wfId, id));
      }

      if (RetryStrategy.NONE.toString().equalsIgnoreCase(action)
          || RetryStrategy.RETRY.toString().equalsIgnoreCase(action)) {
        getWorkflowService().resume(wfId, Collections.singletonMap("retryStrategy", action));
        return ok();
      }

      if (WORKFLOW_ACTION_STOP.equalsIgnoreCase(action)) {
        getWorkflowService().stop(wfId);
        return ok();
      }

      return badRequest("Action not supported: " + action);
    } catch (NotFoundException e) {
      return notFound("Workflow not found: '%d'.", wfId);
    } catch (IllegalStateException e) {
      return badRequest(String.format("Action %s not allowed for current workflow state. EventId: %s", action, id));
    } catch (UnauthorizedException e) {
      return forbidden();
    } catch (Exception e) {
      return serverError();
    }
  }

  @DELETE
  @Path("{eventId}/workflows/{workflowId}")
  @Operation(
      summary = "Delete a workflow of an event",
      description = "Deletes a workflow"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "400",
          description = "When trying to delete the latest workflow of the event."
      ),
      @ApiResponse(responseCode = "404", description = "If the event or the workflow has not been found."),
      @ApiResponse(responseCode = "204", description = "The method does not return any content")
  })
  public Response deleteWorkflow(
      @Parameter(description = "The event identifier", required = true)
      @PathParam("eventId") String id,
      @Parameter(description = "The workflow identifier", required = true)
      @PathParam("workflowId") long wfId
  ) throws SearchIndexException {
    final Optional<Event> optEvent = getIndexService().getEvent(id, getIndex());
    try {
      if (optEvent.isEmpty()) {
        return notFound("Cannot find an event with id '%s'.", id);
      }

      final WorkflowInstance wfInstance = getWorkflowService().getWorkflowById(wfId);
      if (!wfInstance.getMediaPackage().getIdentifier().toString().equals(id)) {
        return badRequest(String.format("Workflow %s is not associated to event %s", wfId, id));
      }

      if (wfId == optEvent.get().getWorkflowId()) {
        return badRequest(String.format("Cannot delete current workflow %s from event %s."
          + " Only older workflows can be deleted.", wfId, id));
      }

      getWorkflowService().remove(wfId);

      return Response.noContent().build();
    } catch (WorkflowStateException e) {
      return badRequest("Deleting is not allowed for current workflow state. EventId: " + id);
    } catch (NotFoundException e) {
      return notFound("Workflow not found: '%d'.", wfId);
    } catch (UnauthorizedException e) {
      return forbidden();
    } catch (Exception e) {
      return serverError();
    }
  }

  private Optional<Event> checkAgentAccessForEvent(final String eventId)
          throws UnauthorizedException, SearchIndexException {
    final Optional<Event> event = getIndexService().getEvent(eventId, getIndex());
    if (event.isEmpty() || !event.get().getEventStatus().contains("SCHEDULE")) {
      return event;
    }
    SecurityUtil.checkAgentAccess(getSecurityService(), event.get().getAgentId());
    return event;
  }

  private void checkAgentAccessForAgent(final String agentId) throws UnauthorizedException {
    SecurityUtil.checkAgentAccess(getSecurityService(), agentId);
  }


  /** Read a JSON array of event identifiers into a list. */
  private static List<String> toIdList(String json) {
    final List<String> ids = new ArrayList<>();
    GsonUtil.gson().fromJson(json, JsonArray.class).forEach(id -> ids.add(id.getAsString()));
    return ids;
  }

  /** Wrap one object in an array, which updateAllEventMetadata expects. */
  private static JsonArray singletonArray(JsonObject element) {
    final JsonArray array = new JsonArray();
    array.add(element);
    return array;
  }

}
