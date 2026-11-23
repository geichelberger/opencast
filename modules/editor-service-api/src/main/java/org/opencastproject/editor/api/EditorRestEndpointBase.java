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

package org.opencastproject.editor.api;


import org.opencastproject.security.api.UnauthorizedException;
import org.opencastproject.util.RestUtil;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;

/**
 * The REST endpoint for the {@link EditorService} service
 */
public abstract class EditorRestEndpointBase {
  /** The logger */
  private static final Logger logger = LoggerFactory.getLogger(EditorRestEndpointBase.class);

  /** The service */
  protected EditorService editorService;

  public abstract void setEditorService(EditorService service);

  @GET
  @Path("{mediaPackageId}/edit.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the data to start the editor",
      description = "Returns all the information required to get the editor tool started"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Media package found"),
      @ApiResponse(responseCode = "404", description = "Media package not found"),
      @ApiResponse(responseCode = "400", description = "The media package has no internal publication."),
      @ApiResponse(responseCode = "403", description = "The user has no write access to the event."),
      @ApiResponse(responseCode = "500", description = "The editing data could not be retrieved.")
  })
  public Response getEditorData(
      @Parameter(description = "The id of the media package", required = true)
      @PathParam("mediaPackageId") final String mediaPackageId
  ) {
    try {
      EditingData response = editorService.getEditData(mediaPackageId);
      if (response != null) {
        return Response.ok(response.toString(), MediaType.APPLICATION_JSON_TYPE).build();
      } else {
        logger.error("EditorService returned empty response");
        return RestUtil.R.serverError();
      }
    } catch (EditorServiceException e) {
      return checkErrorState(mediaPackageId, e);
    } catch (UnauthorizedException e) {
      return Response.status(Response.Status.FORBIDDEN).entity("No write access to this event.").build();
    }
  }

  @POST
  @Path("{mediaPackageId}/lock")
  @Operation(
      summary = "Lock a media package for editing",
      description = "Creates and updates the lock for a mediapackage in the editor. "
          + "Requests will create/refreshen a lock at /editor/{mediapackageId}/lock{uuid} "
          + "(see Location header in response) that will expire after the configured period. "
          + "Subsequent calls must have the same uuid, which will then freshen the lock."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "201", description = "Lock obtained"),
      @ApiResponse(responseCode = "409", description = "Lock not obtained"),
      @ApiResponse(responseCode = "404", description = "Mediapackage not found"),
      @ApiResponse(responseCode = "400", description = "The lock request could not be processed.")
  })
  public Response lockMediapackage(
      @Parameter(description = "The id of the media package", required = true)
      @PathParam("mediaPackageId") final String mediaPackageId,
      @Parameter(
          description = "The user requesting to lock this mediapackage",
          required = true,
          schema = @Schema(example = "admin")
      )
      @FormParam("user") final String user,
      @Parameter(description = "The unique identitier of the lock", required = true)
      @FormParam("uuid") final String uuid,
      @Context HttpServletRequest request
  ) {
    try {
      LockData lockData = new LockData(uuid, user);
      editorService.lockMediaPackage(mediaPackageId, lockData);
      return RestUtil.R.created(new URI(request.getRequestURI() + "/" + lockData.getUUID()));
    } catch (EditorServiceException e) {
      return checkErrorState(mediaPackageId, e);
    } catch (Exception e) {
      logger.debug("Unable to create lock",  e);
      return RestUtil.R.badRequest();
    }
  }

  @DELETE
  @Path("{mediaPackageId}/lock/{uuid}")
  @Operation(
      summary = "Unlock a media package",
      description = "Releases the lock for a mediapackage in the editor"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Lock deleted"),
      @ApiResponse(responseCode = "409", description = "Lock not obtained"),
      @ApiResponse(responseCode = "404", description = "Lock not found")
  })

  public Response unlockMediapackage(
      @Parameter(description = "The id of the media package", required = true)
      @PathParam("mediaPackageId") final String mediaPackageId,
      @Parameter(description = "Identifier of editor session", required = true)
      @PathParam("uuid") final String uuid
  ) {
    try {
      editorService.unlockMediaPackage(mediaPackageId, new LockData(uuid, ""));
      return RestUtil.R.ok();
    } catch (EditorServiceException e) {
      return checkErrorState(mediaPackageId, e);
    }
  }

  @POST
  @Path("{mediaPackageId}/edit.json")
  @Consumes(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Save and process the editing information",
      description = "Takes editing information from the client side and processes it"
  )
  @RequestBody(
      description = "The editing information as JSON",
      required = true,
      content = @Content(mediaType = MediaType.APPLICATION_JSON, schema = @Schema(type = "object"))
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Editing information saved and processed"),
      @ApiResponse(responseCode = "404", description = "Media package not found"),
      @ApiResponse(responseCode = "400", description = "The editing information cannot be parsed"),
      @ApiResponse(responseCode = "423", description = "A workflow is active for the media package."),
      @ApiResponse(
          responseCode = "500",
          description = "The editing information could not be saved or the workflow could not be started."
      )
  })
  public Response editVideo(
      @Parameter(description = "The id of the media package", required = true)
      @PathParam("mediaPackageId") final String mediaPackageId,
      @Context HttpServletRequest request
  ) {
    String details = null;
    try {
      details = readInputStream(request);
      logger.debug("Editor POST-Request received: {}", details);
      EditingData editingInfo = EditingData.parse(details);
      editorService.setEditData(mediaPackageId, editingInfo);
    } catch (EditorServiceException e) {
      return checkErrorState(mediaPackageId, e);
    } catch (Exception e) {
      logger.debug("Unable to parse editing information ({})", details, e);
      return RestUtil.R.badRequest("Unable to parse details");
    }

    return RestUtil.R.ok();
  }

  protected String readInputStream(HttpServletRequest request) {
    String details;
    try (InputStream is = request.getInputStream()) {
      details = IOUtils.toString(is, request.getCharacterEncoding());
    } catch (IOException e) {
      logger.error("Error reading request body:", e);
      return null;
    }
    return details;
  }

  protected Response checkErrorState(final String eventId, EditorServiceException e) {
    switch (e.getErrorStatus()) {
      case MEDIAPACKAGE_NOT_FOUND:
        return RestUtil.R.notFound(String.format("Event '%s' not Found", eventId), MediaType.TEXT_PLAIN_TYPE);
      case MEDIAPACKAGE_LOCKED:
        return RestUtil.R.conflict(String.format("Event '%s' is %s", eventId, e.getMessage()));
      case WORKFLOW_ACTIVE:
        return RestUtil.R.locked();
      case NOT_AUTHORIZED:
        return RestUtil.R.unauthorized(String.format("Unauthorized for event '%s'", eventId));
      case WORKFLOW_NOT_FOUND:
      case METADATA_UPDATE_FAIL:
      case NO_INTERNAL_PUBLICATION:
        return RestUtil.R.badRequest(e.getMessage());
      case UNABLE_TO_CREATE_CATALOG:
      case WORKFLOW_ERROR:
      case UNKNOWN:
      default:
        return RestUtil.R.serverError();
    }
  }

  @GET
  @Path("{mediaPackageId}/metadata.json")
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
      @ApiResponse(responseCode = "404", description = "No event with this identifier was found."),
      @ApiResponse(responseCode = "500", description = "The metadata of the event could not be retrieved.")
  })
  public Response getEventMetadata(
      @Parameter(description = "The event id", required = true)
      @PathParam("mediaPackageId") String eventId
  ) {
    try {
      String response = editorService.getMetadata(eventId);
      if (response != null) {
        return Response.ok(response, MediaType.APPLICATION_JSON_TYPE).build();
      } else {
        logger.error("EditorService returned empty response");
        return RestUtil.R.serverError();
      }
    } catch (EditorServiceException e) {
      return checkErrorState(eventId, e);
    }
  }
}
