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
package org.opencastproject.lti;

import org.opencastproject.lti.service.api.LtiFileUpload;
import org.opencastproject.lti.service.api.LtiService;
import org.opencastproject.security.api.UnauthorizedException;
import org.opencastproject.util.NotFoundException;

import com.google.gson.Gson;

import org.apache.commons.fileupload.FileItemIterator;
import org.apache.commons.fileupload.FileItemStream;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.commons.fileupload.util.Streams;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
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
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * The endpoint for the LTI gui
 */
@Path("/lti-service-gui")
@Tag(
    name = "LTI Service GUI",
    description = "Provides operations to LTI clients"
)
@Component(
    immediate = true,
    service = LtiServiceGuiEndpoint.class,
    property = {
        "service.description=LTI Service GUI",
        "opencast.service.type=org.opencastproject.lti.service.remote",
        "opencast.service.path=/lti-service-gui"
    }
)
@JaxrsResource
public class LtiServiceGuiEndpoint {
  /* OSGi service references */
  private LtiService service;

  /** OSGi DI */
  @Reference
  public void setService(LtiService service) {
    this.service = service;
  }

  @GET
  @Path("/new/metadata")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the metadata fields for a new event",
      description = "Returns the list of metadata fields, with empty values, that can be set for a new event."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The metadata fields as JSON.")
  })
  public Response getNewEventMetadata() {
    return Response.ok(this.service.getNewEventMetadata(), MediaType.APPLICATION_JSON).build();
  }

  @GET
  @Path("/{eventId}/metadata")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the metadata of an event",
      description = "Returns the list of metadata fields of an event, including their current values."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The metadata of the event as JSON."),
      @ApiResponse(responseCode = "401", description = "The user is not allowed to access the event."),
      @ApiResponse(responseCode = "404", description = "The specified event does not exist.")
  })
  public Response getEventMetadata(
      @Parameter(description = "The event identifier", required = true)
      @PathParam("eventId") final String eventId
  ) {
    try {
      return Response.ok(this.service.getEventMetadata(eventId), MediaType.APPLICATION_JSON).build();
    } catch (NotFoundException e) {
      return Response.status(Status.NOT_FOUND).build();
    } catch (UnauthorizedException e) {
      return Response.status(Status.UNAUTHORIZED).build();
    }
  }

  @POST
  @Path("/{eventId}/metadata")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Update the metadata of an event",
      description = "Replaces the metadata of an event with the given metadata."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The metadata has been updated."),
      @ApiResponse(responseCode = "401", description = "The user is not allowed to access the event."),
      @ApiResponse(responseCode = "404", description = "The specified event does not exist.")
  })
  public Response setEventMetadata(
      @Parameter(description = "The event identifier", required = true)
      @PathParam("eventId") final String eventId,
      @Parameter(description = "The new metadata of the event as JSON", required = true)
      @FormParam("metadataJson") final String metadataJson
  ) {
    try {
      this.service.setEventMetadataJson(eventId, metadataJson);
      return Response.ok().build();
    } catch (NotFoundException e) {
      return Response.status(Status.NOT_FOUND).build();
    } catch (UnauthorizedException e) {
      return Response.status(Status.UNAUTHORIZED).build();
    }
  }

  @POST
  @Path("/{eventId}/copy")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Copy an event to a series",
      description = "Copies an event into a different series."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The event has been copied.")
  })
  public Response copyEventToSeries(
      @Parameter(description = "The identifier of the event to copy", required = true)
      @PathParam("eventId") final String eventId,
      @Parameter(description = "The identifier of the series to copy the event into", required = true)
      @QueryParam("target_series") final String targetSeries
  ) {
    this.service.copyEventToSeries(eventId, targetSeries);
    return Response.ok().build();
  }

  @GET
  @Path("/jobs")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "List the running jobs of a series",
      description = "Returns the currently running jobs of a series as a JSON list of objects with the "
          + "fields title and status."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The list of jobs as JSON.")
  })
  public Response listJobs(
      @Parameter(description = "The series identifier", required = true)
      @QueryParam("seriesId") String seriesId
  ) {
    final List<Map<String, String>> results = service.listJobs(seriesId).stream().map(e -> {
      Map<String, String> eventMap = new HashMap<>();
      eventMap.put("title", e.getTitle());
      eventMap.put("status", e.getStatus());
      return eventMap;
    }).collect(Collectors.toList());
    return Response.status(Status.OK).entity(new Gson().toJson(results, List.class)).build();
  }

  @POST
  @Path("/")
  @Consumes(MediaType.MULTIPART_FORM_DATA)
  @Operation(
      summary = "Upload an event",
      description = "Creates a new event, or updates an existing one if an event id is given, in a multipart "
          + "request. The parts are read in order: all parts except the video file have to come before it, and "
          + "every part with a name that is not listed is taken as the video file."
  )
  @RequestBody(
      content = {
          @Content(
              mediaType = MediaType.MULTIPART_FORM_DATA,
              schema = @Schema(type = "object"),
              schemaProperties = {
                  @SchemaProperty(
                      name = "eventId",
                      schema = @Schema(type = "string", description = "ID of the event to update (if it is an update)")
                  ),
                  @SchemaProperty(name = "metadata", schema = @Schema(type = "string", description = "Event metadata")),
                  @SchemaProperty(name = "captions", schema = @Schema(type = "string", description = "Caption file")),
                  @SchemaProperty(
                      name = "captionFormat",
                      schema = @Schema(type = "string", description = "Caption file format")
                  ),
                  @SchemaProperty(
                      name = "captionLanguage",
                      schema = @Schema(type = "string", description = "Caption language")
                  ),
                  @SchemaProperty(
                      name = "seriesId",
                      schema = @Schema(type = "string", description = "Series id of the event")
                  ),
                  @SchemaProperty(
                      name = "presenter",
                      schema = @Schema(type = "string", format = "binary", description = "Presenter movie track")
                  )
              }
          )
      }
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "A new event is created or the event is updated."),
      @ApiResponse(responseCode = "401", description = "No authorization to create or update the event."),
      @ApiResponse(responseCode = "404", description = "The event to be updated wasn't found."),
      @ApiResponse(responseCode = "500", description = "The request could not be read.")
  })
  public Response createNewEvent(
      @HeaderParam("Accept") String acceptHeader,
      @Context HttpServletRequest request
  ) {
    String seriesId = "";
    try {
      String captions = null;
      String captionFormat = null;
      String captionLanguage = null;
      String metadata = null;
      String eventId = null;
      for (FileItemIterator iter = new ServletFileUpload().getItemIterator(request); iter.hasNext();) {
        final FileItemStream item = iter.next();
        final String fieldName = item.getFieldName();
        if ("eventId".equals(fieldName)) {
          eventId = Streams.asString(item.openStream());
        } else if ("metadata".equals(fieldName)) {
          metadata = Streams.asString(item.openStream());
        } else if ("captions".equals(fieldName)) {
          captions = Streams.asString(item.openStream());
        } else if ("captionFormat".equals(fieldName)) {
          captionFormat = Streams.asString(item.openStream());
        } else if ("captionLanguage".equals(fieldName)) {
          captionLanguage = Streams.asString(item.openStream());
        } else if ("seriesId".equals(fieldName)) {
          final String fieldValue = Streams.asString(item.openStream());
          if (!fieldValue.isEmpty()) {
            seriesId = fieldValue;
          }
        } else {
          service.upsertEvent(
                  new LtiFileUpload(item.openStream(), item.getName()),
                  captions,
                  captionFormat,
                  captionLanguage,
                  eventId,
                  seriesId,
                  metadata);
          return Response.ok().build();
        }
      }
      service.upsertEvent(
              null,
              captions,
              captionFormat,
              captionLanguage,
              eventId,
              seriesId,
              metadata);
      return Response.ok().build();
    } catch (FileUploadException | IOException e) {
      return Response.status(Status.INTERNAL_SERVER_ERROR).entity("error while uploading").build();
    } catch (NotFoundException e) {
      return Response.status(Status.NOT_FOUND).build();
    } catch (UnauthorizedException e) {
      return Response.status(Status.UNAUTHORIZED).build();
    }
  }

  @DELETE
  @Path("{eventId}")
  @Operation(
      summary = "Delete an event",
      description = "Deletes an event."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "The event has been deleted."),
      @ApiResponse(responseCode = "401", description = "Not allowed to delete the event."),
      @ApiResponse(responseCode = "404", description = "The specified event does not exist.")
  })
  public Response deleteEvent(
      @HeaderParam("Accept") String acceptHeader,
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") String id
  ) {
    try {
      service.delete(id);
      return Response.noContent().build();
    } catch (UnauthorizedException e) {
      return Response.status(Status.UNAUTHORIZED).build();
    }
  }
}
