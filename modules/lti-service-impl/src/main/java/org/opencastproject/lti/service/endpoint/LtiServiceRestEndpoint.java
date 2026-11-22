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
package org.opencastproject.lti.service.endpoint;


import org.opencastproject.lti.service.api.LtiFileUpload;
import org.opencastproject.lti.service.api.LtiJob;
import org.opencastproject.lti.service.api.LtiService;
import org.opencastproject.security.api.UnauthorizedException;
import org.opencastproject.util.NotFoundException;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import org.apache.commons.fileupload.FileItemIterator;
import org.apache.commons.fileupload.FileItemStream;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.commons.fileupload.util.Streams;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

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
 * The REST endpoint for the remote LTI service (for multi-node setups with LTI)
 */
@Path("/lti-service")
@Tag(
    name = "LTI Service",
    description = "Provides operations to LTI clients"
)
@Component(
    immediate = true,
    service = LtiServiceRestEndpoint.class,
    property = {
        "service.description=LTI Service",
        "opencast.service.type=org.opencastproject.lti.service",
        "opencast.service.path=/lti-service"
    }
)
@JaxrsResource
public class LtiServiceRestEndpoint {
  private static final Gson gson = new Gson();

  /* OSGi service references */
  private LtiService service;

  /** OSGi DI */
  @Reference
  public void setService(LtiService service) {
    this.service = service;
  }

  @GET
  @Path("/jobs")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "List the recent jobs of a series",
      description = "List recent jobs for a specific series."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The list of jobs")
  })
  public Response listJobs(
      @Parameter(description = "The id of the series you want jobs for", required = true)
      @QueryParam("seriesId") String seriesId
  ) {
    return Response.status(Status.OK)
            .entity(gson.toJson(service.listJobs(seriesId), new TypeToken<List<LtiJob>>() {
            }.getType())).build();
  }

  @POST
  @Path("/")
  @Consumes(MediaType.MULTIPART_FORM_DATA)
  @Operation(
      summary = "Create an event",
      description = "Creates an event by sending metadata in a multipart request."
  )
  @RequestBody(
      content = {
          @Content(
              mediaType = MediaType.MULTIPART_FORM_DATA,
              schema = @Schema(type = "object", requiredProperties = {"metadata", "presenter"}),
              schemaProperties = {
                  @SchemaProperty(name = "metadata", schema = @Schema(type = "string", description = "Event metadata")),
                  @SchemaProperty(
                      name = "presenter",
                      schema = @Schema(
                          type = "string", format = "binary",
                          description = "Presenter movie track"
                      )
                  ),
                  @SchemaProperty(name = "captions", schema = @Schema(type = "string", description = "Caption file")),
                  @SchemaProperty(
                      name = "captionFormat",
                      schema = @Schema(
                          type = "string",
                          description = "Caption file format"
                      )
                  ),
                  @SchemaProperty(
                      name = "captionLanguage",
                      schema = @Schema(
                          type = "string",
                          description = "Caption language"
                      )
                  ),
                  @SchemaProperty(
                      name = "isPartOf",
                      schema = @Schema(
                          type = "string",
                          description = "Series id of the event"
                      )
                  ),
                  @SchemaProperty(
                      name = "eventId",
                      schema = @Schema(
                          type = "string",
                          description = "ID of the event to update (if it's an update)"
                      )
                  )
              }
          )
      }
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "A new event is created or the event is updated"),
      @ApiResponse(responseCode = "401", description = "No authorization to create or update events"),
      @ApiResponse(responseCode = "404", description = "The event to be updated wasn't found")
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
      String eventId = null;
      String metadataJson = null;
      for (FileItemIterator iter = new ServletFileUpload().getItemIterator(request); iter.hasNext();) {
        final FileItemStream item = iter.next();
        final String fieldName = item.getFieldName();
        if ("isPartOf".equals(fieldName)) {
          final String fieldValue = Streams.asString(item.openStream());
          if (!fieldValue.isEmpty()) {
            seriesId = fieldValue;
          }
        } else if ("metadata".equals(fieldName)) {
          metadataJson = Streams.asString(item.openStream());
        } else if ("captions".equals(fieldName)) {
          captions = Streams.asString(item.openStream());
        } else if ("captionFormat".equals(fieldName)) {
          captionFormat = Streams.asString(item.openStream());
        } else if ("captionLanguage".equals(fieldName)) {
          captionLanguage = Streams.asString(item.openStream());
        } else if ("eventId".equals(fieldName)) {
          eventId = Streams.asString(item.openStream());
        } else {
          final InputStream stream = item.openStream();
          final String streamName = item.getName();
          service.upsertEvent(
                  new LtiFileUpload(stream, streamName),
                  captions,
                  captionFormat,
                  captionLanguage,
                  eventId,
                  seriesId,
                  metadataJson);
          return Response.ok().build();
        }
      }
      if (eventId == null) {
        return Response.status(Status.BAD_REQUEST).entity("No file given").build();
      }
      service.upsertEvent(null, captions, captionFormat, captionLanguage, eventId, seriesId, metadataJson);
      return Response.ok().build();
    } catch (FileUploadException | IOException e) {
      return Response.status(Status.INTERNAL_SERVER_ERROR).entity("error while uploading").build();
    } catch (NotFoundException e) {
      return Response.status(Status.NOT_FOUND).build();
    } catch (UnauthorizedException e) {
      return Response.status(Status.UNAUTHORIZED).build();
    }
  }

  @POST
  @Path("{eventId}/copy")
  @Operation(
      summary = "Copy an event to a series",
      description = "Copy an event to a different series"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "The event has been copied."),
      @ApiResponse(responseCode = "404", description = "The specified event does not exist.")
  })
  public Response copyEventToSeries(
      @Parameter(description = "The event (id) to copy", required = true)
      @PathParam("eventId") final String eventId,
      @Parameter(description = "The series (id) to copy into", required = true)
      @QueryParam("seriesId") final String seriesId
  ) {
    service.copyEventToSeries(eventId, seriesId);
    return Response.noContent().build();
  }

  @POST
  @Path("{eventId}/metadata")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Set the metadata of an event",
      description = "Set the metadata of an existing event"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The event's metadata has been set"),
      @ApiResponse(responseCode = "404", description = "The event doesn't exist"),
      @ApiResponse(responseCode = "401", description = "The event cannot be accessed")
  })
  public Response setEventMetadataJson(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") final String eventId,
      @Parameter(description = "Event metadata", required = true)
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

  @GET
  @Path("new/metadata")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the metadata of a new event",
      description = "Get the metadata of a new event"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "A new event's metadata")
  })
  public Response getNewEventMetadata() {
    return Response.ok(service.getNewEventMetadata(), MediaType.APPLICATION_JSON).build();
  }

  @GET
  @Path("{eventId}/metadata")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the metadata of an event",
      description = "Get the metadata of an existing event"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Metadata is available and will be returned"),
      @ApiResponse(responseCode = "404", description = "The event doesn't exist"),
      @ApiResponse(responseCode = "401", description = "The event cannot be accessed")
  })
  public Response getEventMetadata(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") final String eventId
  ) {
    try {
      return Response.ok(service.getEventMetadata(eventId), MediaType.APPLICATION_JSON).build();
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
      @ApiResponse(responseCode = "404", description = "The specified event does not exist.")
  })
  public Response deleteEvent(
      @Parameter(description = "The event id", required = true)
      @PathParam("eventId") final String id
  ) {
    try {
      service.delete(id);
      return Response.noContent().build();
    } catch (UnauthorizedException e) {
      return Response.status(Status.UNAUTHORIZED).build();
    }
  }
}
