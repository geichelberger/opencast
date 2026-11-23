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
package org.opencastproject.playlists;

import static javax.servlet.http.HttpServletResponse.SC_BAD_REQUEST;
import static org.apache.commons.lang3.StringUtils.trimToNull;

import org.opencastproject.playlists.serialization.JaxbPlaylist;
import org.opencastproject.search.api.SearchService;
import org.opencastproject.security.api.AuthorizationService;
import org.opencastproject.security.api.UnauthorizedException;
import org.opencastproject.util.NotFoundException;
import org.opencastproject.util.RestUtil;
import org.opencastproject.util.XmlSafeParser;
import org.opencastproject.util.requests.SortCriterion;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationModule;

import org.apache.commons.io.IOUtils;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import javax.ws.rs.DELETE;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.GenericEntity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * A REST endpoint for the {@link PlaylistService}
 */
@Path("/playlists")
@Tag(
    name = "Playlist Service",
    description = "This service lists available playlists and stuff"
)
@Component(
    immediate = true,
    service = PlaylistRestService.class,
    property = {
        "service.description=Playlist REST Endpoint",
        "opencast.service.type=org.opencastproject.playlists",
        "opencast.service.path=/playlists"
    }
)
@JaxrsResource
public class PlaylistRestService {
  /** The logger */
  private static final Logger logger = LoggerFactory.getLogger(PlaylistRestService.class);

  public static final String SAMPLE_PLAYLIST_JSON = "{\n"
      + "        \"title\": \"Opencast Playlist\",\n"
      + "        \"description\": \"This is a playlist about Opencast\",\n"
      + "        \"creator\": \"Opencast\",\n"
      + "        \"entries\": [\n"
      + "            {\n"
      + "                \"contentId\": \"ID-about-opencast\",\n"
      + "                \"type\": \"EVENT\"\n"
      + "            },\n"
      + "            {\n"
      + "                \"contentId\": \"ID-3d-print\",\n"
      + "                \"type\": \"EVENT\"\n"
      + "            }\n"
      + "        ],\n"
      + "        \"accessControlEntries\": [\n"
      + "            {\n"
      + "                \"allow\": true,\n"
      + "                \"role\": \"ROLE_USER_BOB\",\n"
      + "                \"action\": \"read\"\n"
      + "            }\n"
      + "        ]\n"
      + "}";

  public static final String SAMPLE_PLAYLIST_ENTRIES_JSON = "[\n"
      + "            {\n"
      + "                \"contentId\": \"ID-about-opencast\",\n"
      + "                \"type\": \"EVENT\"\n"
      + "            },\n"
      + "            {\n"
      + "                \"contentId\": \"ID-3d-print\",\n"
      + "                \"type\": \"EVENT\"\n"
      + "            }\n"
      + "        ],";

  public static final String SAMPLE_PLAYLIST_XML = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><"
      + "ns3:playlist xmlns:ns2=\"http://mediapackage.opencastproject.org\" "
      + "xmlns:ns3=\"http://playlist.opencastproject.org\"><organization>mh_default_org</organization>"
      + "<entries><contentId>ID-av-portal</contentId><type>EVENT</type></entries><entries>"
      + "<contentId>ID-av-print</contentId><type>EVENT</type></entries><title>Opencast Playlist</title>"
      + "<description>This is a playlist about Opencast</description><creator>Opencast</creator>"
      + "<updated>1701787700848</updated><accessControlEntries><allow>true</allow><role>ROLE_USER_BOB</role>"
      + "<action>read</action></accessControlEntries></ns3:playlist>";

  public static final String SAMPLE_PLAYLIST_ENTRIES_XML =
      "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
      + "<entries>\n"
      + "\t<entry id=\"1061\">\n" + "\t\t<contentId>ID-av-portal</contentId>\n" + "\t\t<type>EVENT</type>\n"
      + "\t</entry>\n"
      + "\t<entry id=\"1062\">\n" + "\t\t<contentId>ID-av-print</contentId>\n" + "\t\t<type>EVENT</type>\n"
      + "\t</entry>\n" + "</entries>";

  /** The playlist service instance */
  private PlaylistService service;

  /** The search service */
  protected SearchService searchService = null;

  /** The authorization service */
  protected AuthorizationService authorizationService = null;

  /**
   * Sets the playlist service
   *
   * @param service
   *          the playlist service instance
   */
  @Reference
  public void setService(PlaylistService service) {
    this.service = service;
  }

  @Reference
  protected void setSearchService(SearchService searchService) {
    this.searchService = searchService;
  }

  @Reference
  public void setAuthorizationService(AuthorizationService authorizationService) {
    this.authorizationService = authorizationService;
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("{id}.json")
  @Operation(
      summary = "Get a playlist as JSON",
      description = "Get a playlist."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "A playlist as JSON."),
      @ApiResponse(responseCode = "404", description = "No playlist with that identifier exists."),
      @ApiResponse(responseCode = "401", description = "Not authorized to perform this action")
  })
  public Response getPlaylistAsJson(
      @Parameter(description = "The playlist identifier", required = true)
      @PathParam("id") String id,
      @Parameter(
          description = "If available publications for"
              + "the content should be returned. Only works for content of type EVENT.",
          example = "true"
      )
      @QueryParam("withPublications") boolean withPublications
  ) throws NotFoundException, UnauthorizedException {
    Playlist playlist = service.getPlaylistById(id);

    JaxbPlaylist jaxbPlaylist;
    if (withPublications) {
      jaxbPlaylist = service.enrich(playlist);
    } else {
      jaxbPlaylist = new JaxbPlaylist(playlist);
    }

    return Response.ok().entity(jaxbPlaylist).build();
  }

  @GET
  @Produces(MediaType.APPLICATION_XML)
  @Path("{id}.xml")
  @Operation(
      summary = "Get a playlist as XML",
      description = "Get a playlist."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "A playlist as XML."),
      @ApiResponse(responseCode = "404", description = "No playlist with that identifier exists."),
      @ApiResponse(responseCode = "401", description = "Not authorized to perform this action")
  })
  public Response getPlaylistAsXml(
      @Parameter(description = "The playlist identifier", required = true)
      @PathParam("id") String id,
      @Parameter(
          description = "If available publications for"
              + "the content should be returned. Only works for content of type EVENT.",
          example = "true"
      )
      @QueryParam("withPublications") boolean withPublications
  ) throws NotFoundException, UnauthorizedException {
    return getPlaylistAsJson(id, withPublications);
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("playlists.json")
  @Operation(
      summary = "List playlists as JSON",
      description = "Get playlists. Playlists that you do not have read access to will not show up."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "A playlist as JSON."),
      @ApiResponse(responseCode = "400", description = "A request parameter was illegal.")
  })
  public Response getPlaylistsAsJson(
      @Parameter(description = "The maximum number of results to return for a single request.", example = "100")
      @QueryParam("limit") int limit,
      @Parameter(description = "The index of the first result to return.")
      @QueryParam("offset") int offset,
      @Parameter(
          description = "Sort the results based upon a sorting criteria. A criteria is specified as a pair such as:"
              + "<Sort Name>:ASC or <Sort Name>:DESC. Adding the suffix ASC or DESC sets the order as ascending or"
              + "descending order and is mandatory. Sort Name is case sensitive. Supported Sort Names are 'updated'",
          example = "updated:ASC"
      )
      @QueryParam("sort") String sort
  ) throws NotFoundException {
    if (offset < 0) {
      return Response.status(SC_BAD_REQUEST).build();
    }

    if (limit < 0) {
      return Response.status(SC_BAD_REQUEST).build();
    }

    SortCriterion sortCriterion = new SortCriterion("", SortCriterion.Order.None);
    Optional<String> optSort = Optional.ofNullable(trimToNull(sort));
    if (optSort.isPresent()) {
      try {
        sortCriterion = SortCriterion.parse(optSort.get());
      } catch (IllegalArgumentException e) {
        return RestUtil.R.badRequest(String.format(
            "Invalid sort parameter '%s': %s. Expected <field>:ASC or <field>:DESC, supported fields: updated",
            optSort.get(), e.getMessage()));
      }

      switch (sortCriterion.getFieldName()) {
        case "updated":
          break;
        default:
          logger.info("Unknown sort criteria {}", sortCriterion.getFieldName());
          return RestUtil.R.badRequest(String.format(
              "Unknown sort field '%s', supported fields: updated", sortCriterion.getFieldName()));
      }
    }

    List<JaxbPlaylist> jaxbPlaylists = new ArrayList<>();
    for (Playlist playlist : service.getPlaylists(limit, offset, sortCriterion)) {
      jaxbPlaylists.add(new JaxbPlaylist(playlist));
    }

    return Response.ok().entity(new GenericEntity<>(jaxbPlaylists) { }).build();
  }

  @GET
  @Produces(MediaType.APPLICATION_XML)
  @Path("playlists.xml")
  @Operation(
      summary = "List playlists as XML",
      description = "Get playlists. Playlists that you do not have read access to will not show up."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "A playlist as XML."),
      @ApiResponse(responseCode = "400", description = "A request parameter was illegal.")
  })
  public Response getPlaylistsAsXml(
      @Parameter(description = "The maximum number of results to return for a single request.", example = "100")
      @QueryParam("limit") int limit,
      @Parameter(description = "The index of the first result to return.")
      @QueryParam("offset") int offset,
      @Parameter(
          description = "Sort the results based upon a sorting criteria. A criteria is specified as a pair such as:"
              + "<Sort Name>:ASC or <Sort Name>:DESC. Adding the suffix ASC or DESC sets the order as ascending or"
              + "descending order and is mandatory. Sort Name is case sensitive. Supported Sort Names are 'updated'",
          example = "updated:ASC"
      )
      @QueryParam("sort") String sort
  ) throws NotFoundException {
    return getPlaylistsAsJson(limit, offset, sort);
  }

  @POST
  @Produces(MediaType.APPLICATION_JSON)
  @Path("new.json")
  @Operation(
      summary = "Create a playlist from JSON",
      description = "Creates a playlist."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "201", description = "Playlist created."),
      @ApiResponse(responseCode = "401", description = "Not authorized to perform this action"),
      @ApiResponse(responseCode = "500", description = "The playlist could not be created.")
  })
  public Response createAsJson(
      @Parameter(description = "Playlist in JSON format", schema = @Schema(example = SAMPLE_PLAYLIST_JSON))
      @FormParam("playlist") String playlistText
  ) throws UnauthorizedException {
    try {
      // Map JSON to JPA
      Playlist playlist = parseJsonToPlaylist(playlistText);

      // Persist
      playlist = service.update(playlist);
      return Response.status(Response.Status.CREATED).entity(new JaxbPlaylist(playlist)).build();
    } catch (UnauthorizedException e) {
      throw e;
    } catch (Exception e) {
      return Response.serverError().build();
    }
  }

  @POST
  @Produces(MediaType.APPLICATION_XML)
  @Path("new.xml")
  @Operation(
      summary = "Create a playlist from XML",
      description = "Creates a playlist."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Playlist created."),
      @ApiResponse(responseCode = "401", description = "Not authorized to perform this action"),
      @ApiResponse(responseCode = "500", description = "The playlist could not be created.")
  })
  public Response createAsXml(
      @Parameter(description = "Playlist in XML format", schema = @Schema(example = SAMPLE_PLAYLIST_XML))
      @FormParam("playlist") String playlistText
  ) throws UnauthorizedException {
    try {
      // Map XML to JPA
      Playlist playlist = parseXmlToPlaylist(playlistText);

      // Persist
      playlist = service.update(playlist);
      return Response.ok().entity(new JaxbPlaylist(playlist)).build();
    } catch (UnauthorizedException e) {
      throw e;
    } catch (Exception e) {
      return Response.serverError().build();
    }
  }

  @PUT
  @Produces(MediaType.APPLICATION_JSON)
  @Path("{id}.json")
  @Operation(
      summary = "Update a playlist from JSON",
      description = "Updates a playlist."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Playlist updated."),
      @ApiResponse(responseCode = "401", description = "Not authorized to perform this action"),
      @ApiResponse(responseCode = "500", description = "The playlist could not be updated.")
  })
  public Response updateAsJson(
      @Parameter(description = "Playlist identifier", required = true)
      @PathParam("id") String id,
      @Parameter(description = "Playlist in JSON format", schema = @Schema(example = SAMPLE_PLAYLIST_JSON))
      @FormParam("playlist") String playlistText
  ) throws UnauthorizedException {
    try {
      Playlist playlist = service.updateWithJson(id, playlistText);
      return Response.ok().entity(new JaxbPlaylist(playlist)).build();
    } catch (UnauthorizedException e) {
      throw e;
    } catch (Exception e) {
      return Response.serverError().build();
    }
  }

  @PUT
  @Produces(MediaType.APPLICATION_XML)
  @Path("{id}.xml")
  @Operation(
      summary = "Update a playlist from XML",
      description = "Updates a playlist."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Playlist updated."),
      @ApiResponse(responseCode = "401", description = "Not authorized to perform this action"),
      @ApiResponse(responseCode = "500", description = "The playlist could not be updated.")
  })
  public Response updateAsXml(
      @Parameter(description = "Playlist identifier", required = true)
      @PathParam("id") String id,
      @Parameter(description = "Playlist in XML format", schema = @Schema(example = SAMPLE_PLAYLIST_XML))
      @FormParam("playlist") String playlistText
  ) throws UnauthorizedException {
    try {
      XmlMapper xmlMapper = new XmlMapper();
      JsonNode node = xmlMapper.readTree(playlistText.getBytes());

      ObjectMapper jsonMapper = new ObjectMapper();
      jsonMapper.enable(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY);
      String json = jsonMapper.writeValueAsString(node);

      Playlist playlist = service.updateWithJson(id, json);
      return Response.ok().entity(new JaxbPlaylist(playlist)).build();
    } catch (UnauthorizedException e) {
      throw e;
    } catch (Exception e) {
      return Response.serverError().build();
    }
  }

  @DELETE
  @Produces(MediaType.APPLICATION_JSON)
  @Path("{id}")
  @Operation(
      summary = "Remove a playlist",
      description = "Removes a playlist."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Playlist removed."),
      @ApiResponse(responseCode = "404", description = "No playlist with that identifier exists."),
      @ApiResponse(responseCode = "401", description = "Not authorized to perform this action"),
      @ApiResponse(responseCode = "500", description = "The playlist could not be removed.")
  })
  public Response remove(
      @Parameter(description = "Playlist identifier", required = true)
      @PathParam("id") String id
  ) throws NotFoundException, UnauthorizedException {
    try {
      // Persist
      Playlist playlist = service.remove(id);
      return Response.ok().entity(new JaxbPlaylist(playlist)).build();
    } catch (NotFoundException | UnauthorizedException e) {
      throw e;
    } catch (Exception e) {
      return Response.serverError().build();
    }
  }

  @POST
  @Produces(MediaType.APPLICATION_JSON)
  @Path("{id}/entries/new")
  @Operation(
      summary = "Add an entry to a playlist",
      description = "Add entry to playlist."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Playlist updated."),
      @ApiResponse(responseCode = "404", description = "No playlist with that identifier exists."),
      @ApiResponse(responseCode = "401", description = "Not authorized to perform this action"),
      @ApiResponse(responseCode = "500", description = "The playlist could not be changed.")
  })
  public Response addEntry(
      @Parameter(description = "Playlist identifier", required = true)
      @PathParam("id") String playlistId,
      @Parameter(description = "Content identifier")
      @FormParam("contentId") String contentId,
      @Parameter(
          description = "Entry type. Enum. Valid values are EVENT, INACCESSIBLE."
      )
      @FormParam("type") PlaylistEntryType type
  ) throws NotFoundException, UnauthorizedException {
    try {
      Playlist playlist = service.addEntry(playlistId, contentId, type);
      return Response.ok().entity(new JaxbPlaylist(playlist)).build();
    } catch (NotFoundException | UnauthorizedException e) {
      throw e;
    } catch (Exception e) {
      return Response.serverError().build();
    }
  }

  @POST
  @Produces(MediaType.APPLICATION_JSON)
  @Path("{id}/entries/{entryId}")
  @Operation(
      summary = "Remove an entry from a playlist",
      description = "Remove entry from playlist."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Playlist updated."),
      @ApiResponse(responseCode = "404", description = "No playlist or entry with that identifier exists."),
      @ApiResponse(responseCode = "401", description = "Not authorized to perform this action"),
      @ApiResponse(responseCode = "500", description = "The playlist could not be changed.")
  })
  public Response addEntry(
      @Parameter(description = "Identifier of the playlist to delete from", required = true)
      @PathParam("id") String playlistId,
      @Parameter(description = "Identifier of the entry that should be deleted", required = true)
      @PathParam("entryId") Long entryId
  ) throws NotFoundException, UnauthorizedException {
    try {
      Playlist playlist = service.removeEntry(playlistId, entryId);
      return Response.ok().entity(new JaxbPlaylist(playlist)).build();
    } catch (NotFoundException | UnauthorizedException e) {
      throw e;
    } catch (Exception e) {
      return Response.serverError().build();
    }
  }

  /**
   * While jackson takes care of automatically converting JAXB to JSON when returning from a request, getting it to
   * parse JSON to JAXB when accepting a request is not that automatic. This functions takes care of that.
   * @param json Valid JSON as a string
   * @return A Playlist containing the information from the JSON
   * @throws IOException
   */
  public Playlist parseJsonToPlaylist(String json) throws IOException {
    JaxbAnnotationModule module = new JaxbAnnotationModule();
    ObjectMapper objectMapper = new ObjectMapper();
    objectMapper.registerModule(module);

    JaxbPlaylist jaxbPlaylist = objectMapper.readValue(json, JaxbPlaylist.class);
    return jaxbPlaylist.toPlaylist();
  }

  private Playlist parseXmlToPlaylist(String xml) throws JAXBException, IOException, SAXException {
    JAXBContext context = JAXBContext.newInstance(JaxbPlaylist.class);
    JaxbPlaylist jaxbPlaylist = context.createUnmarshaller()
        .unmarshal(XmlSafeParser.parse(IOUtils.toInputStream(xml, "UTF8")), JaxbPlaylist.class)
        .getValue();
    return jaxbPlaylist.toPlaylist();
  }
}
