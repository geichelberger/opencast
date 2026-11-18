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

import static org.apache.commons.lang3.StringUtils.trimToNull;
import static org.opencastproject.index.service.util.JSONUtils.safeString;
import static org.opencastproject.index.service.util.RestUtils.okJsonList;
import static org.opencastproject.playlists.PlaylistRestService.SAMPLE_PLAYLIST_JSON;
import static org.opencastproject.util.DateTimeSupport.toUTC;
import static org.opencastproject.util.RestUtil.getEndpointUrl;

import org.opencastproject.index.service.util.RestUtils;
import org.opencastproject.list.common.query.PlaylistsListQuery;
import org.opencastproject.opensearch.api.SearchIndexException;
import org.opencastproject.opensearch.api.SearchResult;
import org.opencastproject.opensearch.index.OpenSearchIndex;
import org.opencastproject.opensearch.index.objects.event.Event;
import org.opencastproject.opensearch.index.objects.event.EventSearchQuery;
import org.opencastproject.playlists.Playlist;
import org.opencastproject.playlists.PlaylistAccessControlEntry;
import org.opencastproject.playlists.PlaylistEntry;
import org.opencastproject.playlists.PlaylistRestService;
import org.opencastproject.playlists.PlaylistService;
import org.opencastproject.rest.RestConstants;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.security.api.UnauthorizedException;
import org.opencastproject.systems.OpencastConstants;
import org.opencastproject.util.NotFoundException;
import org.opencastproject.util.UrlSupport;
import org.opencastproject.util.data.Tuple;
import org.opencastproject.util.requests.SortCriterion;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Predicate;

import javax.ws.rs.DELETE;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

@Path("/admin-ng/playlists")
@Produces(MediaType.APPLICATION_JSON)
@Tag(
    name = "Admin UI - Playlists",
    description = "This service provides the playlists data for the admin UI."
)
@Component(
    immediate = true,
    service = PlaylistsEndpoint.class,
    property = {
        "service.description=Admin UI - Playlists Endpoint",
        "opencast.service.type=org.opencastproject.adminui.PlaylistsEndpoint",
        "opencast.service.path=/admin-ng/playlists"
    }
)
@JaxrsResource
public class PlaylistsEndpoint {

  /** The logging facility */
  private static final Logger logger = LoggerFactory.getLogger(PlaylistsEndpoint.class);

  private static final int DEFAULT_LIMIT = 100;

  /** Base URL of this endpoint */
  protected String endpointBaseUrl;

  /** The playlists service */
  private PlaylistService service;

  /** The playlists REST service for parsing utilities */
  private PlaylistRestService restService;

  /** The OpenSearch index for looking up event metadata */
  private OpenSearchIndex opensearchIndex;

  /** The security service for organization/user context */
  private SecurityService securityService;

  /** OSGi DI */
  @Reference
  public void setPlaylistService(PlaylistService playlistService) {
    this.service = playlistService;
  }

  @Reference
  public void setPlaylistRestService(PlaylistRestService playlistRestService) {
    this.restService = playlistRestService;
  }

  @Reference
  public void setOpenSearchIndex(OpenSearchIndex opensearchIndex) {
    this.opensearchIndex = opensearchIndex;
  }

  @Reference
  public void setSecurityService(SecurityService securityService) {
    this.securityService = securityService;
  }

  /** OSGi activation method */
  @Activate
  void activate(ComponentContext cc) {
    logger.info("Activating Admin UI - Playlists Endpoint");

    final Tuple<String, String> endpointUrl = getEndpointUrl(cc, OpencastConstants.SERVER_URL_PROPERTY,
        RestConstants.SERVICE_PATH_PROPERTY);
    endpointBaseUrl = UrlSupport.concat(endpointUrl.getA(), endpointUrl.getB());
  }

  @GET
  @Path("{id}")
  @Operation(
      summary = "Get a playlist",
      description = "Get a playlist by ID."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returns the playlist."),
      @ApiResponse(responseCode = "404", description = "The specified playlist does not exist."),
      @ApiResponse(responseCode = "403", description = "The user does not have permission to access this playlist."),
      @ApiResponse(responseCode = "400", description = "The request is invalid or inconsistent.")
  })
  public Response getPlaylist(
      @HeaderParam("Accept") String acceptHeader,
      @Parameter(description = "The playlist identifier", required = true)
      @PathParam("id") String id
  ) {
    try {
      Playlist playlist = service.getPlaylistById(id);
      return Response.ok(playlistToJson(playlist).toString(), MediaType.APPLICATION_JSON_TYPE).build();
    } catch (NotFoundException e) {
      logger.info("Playlist '{}' not found.", id);
      return Response.status(Response.Status.NOT_FOUND).build();
    } catch (UnauthorizedException e) {
      logger.warn("User doesn't have permission to access playlist '{}'.", id);
      return Response.status(Response.Status.FORBIDDEN).build();
    } catch (IllegalStateException e) {
      logger.warn("Invalid state when accessing playlist '{}': {}", id, e.getMessage());
      return Response.status(Response.Status.BAD_REQUEST).build();
    }
  }

  @GET
  @Path("")
  @Operation(
      summary = "Get playlists",
      description = "Get playlists. Playlists that you do not have read access to will not show up."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returns the playlists."),
      @ApiResponse(responseCode = "400", description = "The request is invalid or inconsistent.")
  })
  public Response getPlaylists(
      @HeaderParam("Accept") String acceptHeader,
      @Parameter(description = "The maximum number of results to return for a single request.", example = "100")
      @QueryParam("limit") Integer limit,
      @Parameter(description = "The index of the first result to return.", example = "0")
      @QueryParam("offset") Integer offset,
      @Parameter(
          description = "Sort the results based upon a sorting criteria. Must be in the form '<Sort "
              + "Name>:ASC' or '<Sort Name>:DESC'. Sort Name is case sensitive."
              + " Supported Sort Names are 'updated', 'title', and 'creator'.",
          example = "updated:ASC"
      )
      @QueryParam("sort") String sort,
      @Parameter(
          description = "Filter the results by the given criteria. The format is 'key:value', "
              + "and multiple filters can be combined with commas. Supported filter keys: "
              + "'textFilter' (case-insensitive search across title, description, and creator), "
              + "'creator' (case-insensitive match on the creator field), "
              + "'Updated' (date range in the form 'start/end' using ISO 8601 date-time values).",
          example = "textFilter:opencast,creator:john,Updated:2025-01-01/2026-12-31"
      )
      @QueryParam("filter") String filter
  ) {

    Optional<Integer> optLimit = Optional.ofNullable(limit);
    Optional<Integer> optOffset = Optional.ofNullable(offset);
    Optional<String> optSort = Optional.ofNullable(trimToNull(sort));

    // If the limit is set to 0, this is not taken into account.
    if (optLimit.isPresent() && limit == 0) {
      optLimit = Optional.empty();
    }

    List<Predicate<Playlist>> filterPredicates = new ArrayList<>();

    // Add filters
    Map<String, String> filters = RestUtils.parseFilter(filter);
    for (String name : filters.keySet()) {
      String value = filters.get(name);
      if (PlaylistsListQuery.FILTER_TEXT_NAME.equals(name)) {
        filterPredicates.add(containsIgnoreCase(Playlist::getTitle, value)
            .or(containsIgnoreCase(Playlist::getDescription, value))
            .or(containsIgnoreCase(Playlist::getCreator, value)));
      } else if (PlaylistsListQuery.FILTER_CREATOR_NAME.equals(name)) {
        filterPredicates.add(containsIgnoreCase(Playlist::getCreator, value));
      } else if (PlaylistsListQuery.FILTER_UPDATED_NAME.equals(name)) {
        try {
          Tuple<Date, Date> range = RestUtils.getFromAndToDateRange(value);
          filterPredicates.add(p -> p.getUpdated() != null
              && !p.getUpdated().before(range.getA())
              && !p.getUpdated().after(range.getB()));
        } catch (IllegalArgumentException e) {
          logger.warn("Could not parse Updated filter dates: {}", value);
        }
      } else {
        logger.debug("Unknown filter: {}", name);
      }
    }

    SortCriterion sortCriterion
        = new SortCriterion("updated", SortCriterion.Order.Ascending);
    if (optSort.isPresent()) {
      ArrayList<SortCriterion> sortCriteria
          = RestUtils.parseSortQueryParameter(optSort.get());
      for (SortCriterion criterion : sortCriteria) {
        switch (criterion.getFieldName()) {
          case "updated":
          case "creator":
          case "title":
            sortCriterion = criterion;
            break;
          default:
            logger.warn("Unknown sort criteria: {}",
                criterion.getFieldName());
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
      }
    }

    // Fetch all playlists (filtering is done in memory since
    // playlists are not in the search index). Todo: Add to index?
    List<Playlist> allPlaylists
        = service.getPlaylists(Integer.MAX_VALUE, 0, sortCriterion);

    // Apply filters
    List<Playlist> filteredPlaylists = allPlaylists;
    for (Predicate<Playlist> predicate : filterPredicates) {
      filteredPlaylists = filteredPlaylists.stream()
          .filter(predicate).toList();
    }

    // Apply pagination
    int effectiveOffset = optOffset.orElse(0);
    int effectiveLimit = optLimit.orElse(DEFAULT_LIMIT);
    int actualOffset = Math.min(effectiveOffset, filteredPlaylists.size());
    int endIndex = Math.min(
        actualOffset + effectiveLimit, filteredPlaylists.size());
    List<Playlist> paginatedPlaylists
        = filteredPlaylists.subList(actualOffset, endIndex);

    List<JsonObject> playlistsList = new ArrayList<>();
    for (Playlist p : paginatedPlaylists) {
      playlistsList.add(playlistToJson(p));
    }

    return okJsonList(playlistsList, effectiveOffset, effectiveLimit,
        filteredPlaylists.size());
  }

  @POST
  @Path("")
  @Operation(
      summary = "Create a playlist",
      description = "Creates a new playlist."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "201", description = "Playlist created."),
      @ApiResponse(responseCode = "403", description = "The user does not have permission to create a playlist."),
      @ApiResponse(responseCode = "400", description = "The request is invalid or inconsistent.")
  })
  public Response createPlaylist(
      @HeaderParam("Accept") String acceptHeader,
      @Parameter(
          description = "Playlist in JSON format",
          required = true,
          schema = @Schema(example = SAMPLE_PLAYLIST_JSON)
      )
      @FormParam("playlist") String playlistText
  ) {
    try {
      // Parse JSON to playlist
      Playlist playlist = restService.parseJsonToPlaylist(playlistText);

      // Persist
      playlist = service.update(playlist);

      return Response.created(URI.create(getPlaylistUrl(playlist.getId())))
          .entity(playlistToJson(playlist).toString())
          .type(MediaType.APPLICATION_JSON_TYPE)
          .build();
    } catch (UnauthorizedException e) {
      logger.warn("User doesn't have permission to create playlist.");
      return Response.status(Response.Status.FORBIDDEN).build();
    } catch (IOException | IllegalArgumentException e) {
      logger.warn("Invalid playlist JSON: {}", e.getMessage());
      return Response.status(Response.Status.BAD_REQUEST).build();
    }
  }

  @PUT
  @Path("{id}")
  @Operation(
      summary = "Update a playlist",
      description = "Updates an existing playlist."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Playlist updated."),
      @ApiResponse(responseCode = "403", description = "The user does not have permission to update this playlist."),
      @ApiResponse(responseCode = "400", description = "The request is invalid or inconsistent.")
  })
  public Response updatePlaylist(
      @HeaderParam("Accept") String acceptHeader,
      @Parameter(description = "Playlist identifier", required = true)
      @PathParam("id") String id,
      @Parameter(
          description = "Playlist in JSON format",
          required = true,
          schema = @Schema(example = SAMPLE_PLAYLIST_JSON)
      )
      @FormParam("playlist") String playlistText
  ) {
    try {
      Playlist playlist = service.updateWithJson(id, playlistText);
      return Response.ok(playlistToJson(playlist).toString(), MediaType.APPLICATION_JSON_TYPE).build();
    } catch (UnauthorizedException e) {
      logger.warn("User doesn't have permission to update playlist '{}'.", id);
      return Response.status(Response.Status.FORBIDDEN).build();
    } catch (IOException | IllegalArgumentException e) {
      logger.warn("Invalid playlist JSON: {}", e.getMessage());
      return Response.status(Response.Status.BAD_REQUEST).build();
    }
  }

  @DELETE
  @Path("{id}")
  @Operation(
      summary = "Remove a playlist",
      description = "Removes a playlist."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Playlist removed."),
      @ApiResponse(responseCode = "404", description = "No playlist with that identifier exists."),
      @ApiResponse(responseCode = "403", description = "The user does not have permission to delete this playlist.")
  })
  public Response removePlaylist(
      @HeaderParam("Accept") String acceptHeader,
      @Parameter(description = "Playlist identifier", required = true)
      @PathParam("id") String id
  ) {
    try {
      Playlist playlist = service.remove(id);
      return Response.ok(playlistToJson(playlist).toString(), MediaType.APPLICATION_JSON_TYPE).build();
    } catch (NotFoundException e) {
      logger.info("Playlist '{}' not found.", id);
      return Response.status(Response.Status.NOT_FOUND).build();
    } catch (UnauthorizedException e) {
      logger.warn("User doesn't have permission to delete playlist '{}'.", id);
      return Response.status(Response.Status.FORBIDDEN).build();
    }
  }

  private JsonObject playlistToJson(Playlist playlist) {
    JsonObject json = new JsonObject();

    json.addProperty("id", playlist.getId());

    // Look up event metadata for all entries so the frontend doesn't have to
    Map<String, Event> eventMap = lookupEntryEvents(playlist.getEntries());

    JsonArray entriesArray = new JsonArray();
    for (PlaylistEntry entry : playlist.getEntries()) {
      entriesArray.add(playlistEntryToJson(entry, eventMap.get(entry.getContentId())));
    }
    json.add("entries", entriesArray);

    json.addProperty("title", safeString(playlist.getTitle()));
    json.addProperty("description", safeString(playlist.getDescription()));
    json.addProperty("creator", safeString(playlist.getCreator()));
    json.addProperty("updated", playlist.getUpdated() != null ? toUTC(playlist.getUpdated().getTime()) : "");

    JsonArray aceArray = new JsonArray();
    for (PlaylistAccessControlEntry ace : playlist.getAccessControlEntries()) {
      aceArray.add(playlistAccessControlEntryToJson(ace));
    }
    json.add("accessControlEntries", aceArray);

    return json;
  }

  private JsonObject playlistEntryToJson(PlaylistEntry playlistEntry, Event event) {
    JsonObject json = new JsonObject();

    json.addProperty("id", playlistEntry.getId());
    if (playlistEntry.getContentId() != null) {
      json.addProperty("contentId", playlistEntry.getContentId());
    } else {
      json.add("contentId", null);
    }

    json.add("type", enumToJSON(playlistEntry.getType()));

    // Include event metadata if available
    if (event != null) {
      json.addProperty("title", safeString(event.getTitle()));
      json.addProperty("start_date", safeString(event.getRecordingStartDate()));

      if (event.getSeriesName() != null) {
        JsonObject series = new JsonObject();
        series.addProperty("id", safeString(event.getSeriesId()));
        series.addProperty("title", safeString(event.getSeriesName()));
        json.add("series", series);
      }

      if (event.getPresenters() != null && !event.getPresenters().isEmpty()) {
        JsonArray presenters = new JsonArray();
        for (String presenter : event.getPresenters()) {
          presenters.add(presenter);
        }
        json.add("presenters", presenters);
      }
    }

    return json;
  }

  /**
   * Look up event metadata from search index for all playlist entries.
   */
  private Map<String, Event> lookupEntryEvents(List<PlaylistEntry> entries) {
    Map<String, Event> eventMap = new HashMap<>();
    String org = securityService.getOrganization().getId();
    var user = securityService.getUser();

    for (PlaylistEntry entry : entries) {
      String contentId = entry.getContentId();
      if (contentId == null || contentId.isEmpty()) {
        continue;
      }

      try {
        SearchResult<Event> result = opensearchIndex.getByQuery(
            new EventSearchQuery(org, user).withIdentifier(contentId));
        if (result.getPageSize() != 0) {
          eventMap.put(contentId, result.getItems()[0].getSource());
        }
      } catch (SearchIndexException e) {
        logger.warn("Could not look up event '{}': {}", contentId, e.getMessage());
      }
    }

    return eventMap;
  }

  private JsonObject playlistAccessControlEntryToJson(PlaylistAccessControlEntry ace) {
    JsonObject json = new JsonObject();

    json.addProperty("id", ace.getId());
    json.addProperty("allow", ace.isAllow());
    json.addProperty("role", ace.getRole());
    json.addProperty("action", ace.getAction());

    return json;
  }

  private JsonElement enumToJSON(Enum<?> e) {
    return e == null ? null : new JsonPrimitive(e.toString());
  }

  private String getPlaylistUrl(String playlistId) {
    return UrlSupport.concat(endpointBaseUrl, playlistId);
  }

  /** Build a case-insensitive contains predicate for a string field of a playlist. */
  private static Predicate<Playlist> containsIgnoreCase(Function<Playlist, String> getter, String value) {
    String lower = value.toLowerCase();
    return p -> {
      String field = getter.apply(p);
      return field != null && field.toLowerCase().contains(lower);
    };
  }
}
