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

package org.opencastproject.workingfilerepository.impl;

import static javax.servlet.http.HttpServletResponse.SC_NOT_FOUND;
import static org.opencastproject.util.MimeTypes.getMimeType;
import static org.opencastproject.util.RestUtil.R.ok;
import static org.opencastproject.util.RestUtil.fileResponse;
import static org.opencastproject.util.RestUtil.partialFileResponse;

import org.opencastproject.security.api.SecurityService;
import org.opencastproject.serviceregistry.api.ServiceRegistry;
import org.opencastproject.storage.StorageUsage;
import org.opencastproject.util.MimeTypes;
import org.opencastproject.util.NotFoundException;
import org.opencastproject.util.UnknownFileTypeException;
import org.opencastproject.workingfilerepository.api.PathMappable;
import org.opencastproject.workingfilerepository.api.WorkingFileRepository;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import org.apache.commons.fileupload.FileItemIterator;
import org.apache.commons.fileupload.FileItemStream;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.hc.core5.http.HttpStatus;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.DELETE;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
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
import io.swagger.v3.oas.annotations.media.SchemaProperty;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

@Path("/files")
@Tag(
    name = "Working File Repository",
    description = "Stores and retrieves files for use during media processing."
)
@Component(
    name = "org.opencastproject.workingfilerepository.impl.WorkingFileRepository",
    property = {
      "service.description=Working File Repository REST Endpoint",
      "opencast.service.type=org.opencastproject.files",
      "opencast.service.path=/files"
    },
    immediate = true,
    service = {
            WorkingFileRepositoryRestEndpoint.class,
            WorkingFileRepository.class,
            PathMappable.class,
            StorageUsage.class
    }
)
@JaxrsResource
public class WorkingFileRepositoryRestEndpoint extends WorkingFileRepositoryImpl {

  private static final Logger logger = LoggerFactory.getLogger(WorkingFileRepositoryRestEndpoint.class);

  /**
   * Callback from OSGi that is called when this service is activated.
   *
   * @param cc
   *          OSGi component context
   */
  @Override
  @Activate
  public void activate(ComponentContext cc) throws IOException {
    super.activate(cc);
  }

  /**
   * Callback from OSGi that is called when this service is deactivated.
   */
  @Override
  @Deactivate
  public void deactivate() {
    super.deactivate();
  }

  /**
   * Sets the remote service manager.
   *
   * @param remoteServiceManager
   */
  @Override
  @Reference
  public void setRemoteServiceManager(ServiceRegistry remoteServiceManager) {
    super.setRemoteServiceManager(remoteServiceManager);
  }

  @Override
  @Reference
  public void setSecurityService(SecurityService securityService) {
    super.setSecurityService(securityService);
  }

  @POST
  @Produces(MediaType.TEXT_HTML)
  @Path(WorkingFileRepository.MEDIAPACKAGE_PATH_PREFIX + "{mediaPackageID}/{mediaPackageElementID}")
  @Operation(
      summary = "Store a file of a media package element",
      description = "Store a file in working repository under ./mediaPackageID/mediaPackageElementID"
  )
  @RequestBody(
      content = {
          @Content(
              mediaType = MediaType.MULTIPART_FORM_DATA,
              schema = @Schema(type = "object", requiredProperties = {"file"}),
              schemaProperties = {
                  @SchemaProperty(
                      name = "file",
                      schema = @Schema(
                          type = "string", format = "binary",
                          description = "The file to store"
                      )
                  )
              }
          )
      }
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "OK, file stored")
  })
  public Response restPut(
      @Parameter(description = "the mediapackage identifier", required = true)
      @PathParam("mediaPackageID") String mediaPackageID,
      @Parameter(description = "the mediapackage element identifier", required = true)
      @PathParam("mediaPackageElementID") String mediaPackageElementID,
      @Context HttpServletRequest request
  ) throws Exception {
    if (ServletFileUpload.isMultipartContent(request)) {
      for (FileItemIterator iter = new ServletFileUpload().getItemIterator(request); iter.hasNext();) {
        FileItemStream item = iter.next();
        if (item.isFormField()) {
          continue;

        }
        URI url = this.put(mediaPackageID, mediaPackageElementID, item.getName(), item.openStream());
        return Response.ok(url.toString()).build();
      }
    }
    return Response.serverError().status(400).build();
  }

  @POST
  @Produces(MediaType.TEXT_HTML)
  @Path(WorkingFileRepository.MEDIAPACKAGE_PATH_PREFIX + "{mediaPackageID}/{mediaPackageElementID}/{filename}")
  @Operation(
      summary = "Store a file of a media package element with a file name",
      description = "Store a file in working repository under ./mediaPackageID/mediaPackageElementID/filename"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "OK, file stored")
  })
  public Response restPutURLEncoded(
      @Context HttpServletRequest request,
      @Parameter(description = "the mediapackage identifier", required = true)
      @PathParam("mediaPackageID") String mediaPackageID,
      @Parameter(description = "the mediapackage element identifier", required = true)
      @PathParam("mediaPackageElementID") String mediaPackageElementID,
      @Parameter(description = "the filename", required = true)
      @PathParam("filename") String filename,
      @Parameter(description = "The content of the file")
      @FormParam("content") String content
  ) throws Exception {
    String encoding = request.getCharacterEncoding();
    if (encoding == null) {
      encoding = "utf-8";
    }

    URI url = this.put(mediaPackageID, mediaPackageElementID, filename, IOUtils.toInputStream(content, encoding));
    return Response.ok(url.toString()).build();
  }

  @POST
  @Produces(MediaType.TEXT_HTML)
  @Path(WorkingFileRepository.COLLECTION_PATH_PREFIX + "{collectionId}")
  @Operation(
      summary = "Store a file in a collection",
      description = "Store a file in working repository under ./collectionId/filename"
  )
  @RequestBody(
      content = {
          @Content(
              mediaType = MediaType.MULTIPART_FORM_DATA,
              schema = @Schema(type = "object", requiredProperties = {"file"}),
              schemaProperties = {
                  @SchemaProperty(
                      name = "file",
                      schema = @Schema(
                          type = "string", format = "binary",
                          description = "The file to store"
                      )
                  )
              }
          )
      }
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "OK, file stored")
  })
  public Response restPutInCollection(
      @Parameter(description = "the collection identifier", required = true)
      @PathParam("collectionId") String collectionId,
      @Context HttpServletRequest request
  ) throws Exception {
    if (ServletFileUpload.isMultipartContent(request)) {
      for (FileItemIterator iter = new ServletFileUpload().getItemIterator(request); iter.hasNext();) {
        FileItemStream item = iter.next();
        if (item.isFormField()) {
          continue;

        }
        URI url = this.putInCollection(collectionId, item.getName(), item.openStream());
        return Response.ok(url.toString()).build();
      }
    }
    return Response.serverError().status(400).build();
  }

  @DELETE
  @Path(WorkingFileRepository.MEDIAPACKAGE_PATH_PREFIX + "{mediaPackageID}/{mediaPackageElementID}")
  @Operation(
      summary = "Delete a media package element file",
      description = "Remove the file from the working repository under /mediaPackageID/mediaPackageElementID"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "File deleted"),
      @ApiResponse(responseCode = "404", description = "File did not exist")
  })
  public Response restDelete(
      @Parameter(description = "the mediapackage identifier", required = true)
      @PathParam("mediaPackageID") String mediaPackageID,
      @Parameter(description = "the mediapackage element identifier", required = true)
      @PathParam("mediaPackageElementID") String mediaPackageElementID
  ) {
    try {
      if (delete(mediaPackageID, mediaPackageElementID)) {
        return Response.ok().build();
      } else {
        return Response.status(HttpStatus.SC_NOT_FOUND).build();
      }
    } catch (Exception e) {
      logger.error("Unable to delete element '{}' from mediapackage '{}'", mediaPackageElementID,
              mediaPackageID, e);
      return Response.serverError().entity(e.getMessage()).build();
    }
  }

  @DELETE
  @Path(WorkingFileRepository.COLLECTION_PATH_PREFIX + "{collectionId}/{fileName}")
  @Operation(
      summary = "Delete a file from a collection",
      description = "Remove the file from the working repository under /collectionId/filename"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "File deleted"),
      @ApiResponse(responseCode = "404", description = "Collection or file not found")
  })
  public Response restDeleteFromCollection(
      @Parameter(description = "the collection identifier", required = true)
      @PathParam("collectionId") String collectionId,
      @Parameter(description = "the file name", required = true)
      @PathParam("fileName") String fileName
  ) {
    try {
      if (this.deleteFromCollection(collectionId, fileName)) {
        return Response.noContent().build();
      } else {
        return Response.status(SC_NOT_FOUND).build();
      }
    } catch (Exception e) {
      logger.error("Unable to delete element '{}' from collection '{}'", fileName, collectionId, e);
      return Response.serverError().entity(e.getMessage()).build();
    }
  }

  @DELETE
  @Path(WorkingFileRepository.COLLECTION_PATH_PREFIX + "cleanup/{collectionId}/{numberOfDays}")
  @Operation(
      summary = "Delete old files from a collection",
      description = "Remove the files from the working repository under /collectionId that are older than N days"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "Files deleted"),
      @ApiResponse(responseCode = "404", description = "Collection not found")
  })
  public Response restCleanupOldFilesFromCollection(
      @Parameter(description = "the collection identifier", required = true)
      @PathParam("collectionId") String collectionId,
      @Parameter(description = "files older than this number of days will be deleted", required = true)
      @PathParam("numberOfDays") long days
  ) {
    try {
      if (this.cleanupOldFilesFromCollection(collectionId, days)) {
        return Response.noContent().build();
      } else {
        return Response.status(SC_NOT_FOUND).build();
      }
    } catch (Exception e) {
      logger.error("Unable to delete files older than '{}' days from collection '{}'",
              days, collectionId, e);
      return Response.serverError().entity(e.getMessage()).build();
    }
  }

  @DELETE
  @Path(WorkingFileRepository.COLLECTION_PATH_PREFIX + "cleanup/mediapackage/{numberOfDays}")
  @Operation(
      summary = "Delete old media package files",
      description = "Remove files and directories from the working file repository under /mediapackage that are "
          + "older than N days"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "Files deleted")
  })
  public Response restCleanupOldFilesFromMediaPackage(
      @Parameter(description = "files older than this number of days will be deleted", required = true)
      @PathParam("numberOfDays") long days
  ) {
    try {
      this.cleanupOldFilesFromMediaPackage(days);
      return Response.noContent().build();
    } catch (Exception e) {
      return Response.serverError().entity(e.getMessage()).build();
    }
  }

  @GET
  @Path(WorkingFileRepository.MEDIAPACKAGE_PATH_PREFIX + "{mediaPackageID}/{mediaPackageElementID}")
  @Operation(
      summary = "Get the file of a media package element",
      description = "Gets the file from the working repository under /mediaPackageID/mediaPackageElementID"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "File returned"),
      @ApiResponse(responseCode = "304", description = "If file not modified"),
      @ApiResponse(responseCode = "404", description = "Not found")
  })
  public Response restGet(
      @Parameter(description = "the mediapackage identifier", required = true)
      @PathParam("mediaPackageID") final String mediaPackageID,
      @Parameter(description = "the mediapackage element identifier", required = true)
      @PathParam("mediaPackageElementID") final String mediaPackageElementID,
      @Parameter(description = "The digest of the file the client already has. If it matches, 304 is returned")
      @HeaderParam("If-None-Match") String ifNoneMatch
  ) throws NotFoundException {
    // Check the If-None-Match header first
    String md5 = null;
    try {
      md5 = getMediaPackageElementDigest(mediaPackageID, mediaPackageElementID);
      if (StringUtils.isNotBlank(ifNoneMatch) && md5.equals(ifNoneMatch)) {
        return Response.notModified(md5).build();
      }
    } catch (IOException e) {
      logger.warn("Error reading digest of {}/{}", mediaPackageElementID, mediaPackageElementID);
    }
    try {
      String contentType;
      File file = getFile(mediaPackageID, mediaPackageElementID);
      try {
        contentType = MimeTypes.fromString(file.getPath()).toString();
      } catch (UnknownFileTypeException e) {
        contentType = "application/octet-stream";
      }
      try {
        return ok(
            get(mediaPackageID, mediaPackageElementID),
            contentType,
            Optional.of(file.length()),
            Optional.empty());
      } catch (IOException e) {
        throw new NotFoundException();
      }
    } catch (IllegalStateException e) {
      logger.error("Unable to provide element '{}' from mediapackage '{}'", mediaPackageElementID,
              mediaPackageID, e);
      return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
    }
  }

  @GET
  @Path(WorkingFileRepository.MEDIAPACKAGE_PATH_PREFIX + "{mediaPackageID}/{mediaPackageElementID}/{fileName}")
  @Operation(
      summary = "Get the file of a media package element by file name",
      description = "Gets the file from the working repository under /mediaPackageID/mediaPackageElementID/filename"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "File returned"),
      @ApiResponse(responseCode = "404", description = "Not found")
  })
  public Response restGet(
      @Parameter(description = "the mediapackage identifier", required = true)
      @PathParam("mediaPackageID") String mediaPackageID,
      @Parameter(description = "the mediapackage element identifier", required = true)
      @PathParam("mediaPackageElementID") String mediaPackageElementID,
      @Parameter(description = "the file name", required = true)
      @PathParam("fileName") String fileName,
      @Parameter(description = "The digest of the file the client already has. If it matches, 304 is returned")
      @HeaderParam("If-None-Match") String ifNoneMatch,
      @Parameter(description = "The byte range of the file to return")
      @HeaderParam("Range") String range
  ) throws NotFoundException {
    String md5 = null;
    // Check the If-None-Match header first
    try {
      md5 = getMediaPackageElementDigest(mediaPackageID, mediaPackageElementID);
      if (StringUtils.isNotBlank(ifNoneMatch) && md5.equals(ifNoneMatch)) {
        return Response.notModified(md5).build();
      }
    } catch (IOException e) {
      logger.warn("Error reading digest of {}/{}/{}", mediaPackageElementID, mediaPackageElementID,
              fileName);
    }

    try {
      if (StringUtils.isNotBlank(range)) {
        logger.debug("trying to retrieve range: {}", range);
        return partialFileResponse(getFile(mediaPackageID, mediaPackageElementID), getMimeType(fileName),
                Optional.of(fileName), range).tag(md5).build();

      } else {
        // No If-Non-Match header provided, or the file changed in the meantime
        return fileResponse(getFile(mediaPackageID, mediaPackageElementID), getMimeType(fileName),
                Optional.of(fileName)).tag(md5).build();
      }
    } catch (Exception e) {
      logger.error("Unable to provide element '{}' from mediapackage '{}'", mediaPackageElementID,
              mediaPackageID, e);
      return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
    }
  }

  @GET
  @Path(WorkingFileRepository.COLLECTION_PATH_PREFIX + "{collectionId}/{fileName}")
  @Operation(
      summary = "Get a file from a collection",
      description = "Gets the file from the working repository under /collectionId/filename"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "File returned"),
      @ApiResponse(responseCode = "404", description = "Not found")
  })
  public Response restGetFromCollection(
      @Parameter(description = "the collection identifier", required = true)
      @PathParam("collectionId") String collectionId,
      @Parameter(description = "the file name", required = true)
      @PathParam("fileName") String fileName
  ) throws NotFoundException {
    return fileResponse(getFileFromCollection(collectionId, fileName), getMimeType(fileName), Optional.of(fileName))
            .build();
  }

  @GET
  @Path("/collectionuri/{collectionID}/{fileName}")
  @Operation(
      summary = "Get the URI of a file in a collection",
      description = "Gets the URL for a file to be stored in the working repository under /collectionId/filename"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "URL returned")
  })
  public Response restGetCollectionUri(
      @Parameter(description = "the collection identifier", required = true)
      @PathParam("collectionID") String collectionId,
      @Parameter(description = "the file name", required = true)
      @PathParam("fileName") String fileName
  ) {
    URI uri = this.getCollectionURI(collectionId, fileName);
    return Response.ok(uri.toString()).build();
  }

  @GET
  @Path("/uri/{mediaPackageID}/{mediaPackageElementID}")
  @Operation(
      summary = "Get the URI of a media package element file",
      description = "Gets the URL for a file to be stored in the working repository under /mediaPackageID"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "URL returned")
  })
  public Response restGetUri(
      @Parameter(description = "the mediaPackage identifier", required = true)
      @PathParam("mediaPackageID") String mediaPackageID,
      @Parameter(description = "the mediaPackage element identifier", required = true)
      @PathParam("mediaPackageElementID") String mediaPackageElementID
  ) {
    URI uri = this.getURI(mediaPackageID, mediaPackageElementID);
    return Response.ok(uri.toString()).build();
  }

  @GET
  @Path("/uri/{mediaPackageID}/{mediaPackageElementID}/{fileName}")
  @Operation(
      summary = "Get the URI of a media package element file by file name",
      description = "Gets the URL for a file to be stored in the working repository under /mediaPackageID"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "URL returned")
  })
  public Response restGetUri(
      @Parameter(description = "the mediaPackage identifier", required = true)
      @PathParam("mediaPackageID") String mediaPackageID,
      @Parameter(description = "the mediaPackage element identifier", required = true)
      @PathParam("mediaPackageElementID") String mediaPackageElementID,
      @Parameter(description = "the filename", required = true)
      @PathParam("fileName") String fileName
  ) {
    URI uri = this.getURI(mediaPackageID, mediaPackageElementID, fileName);
    return Response.ok(uri.toString()).build();
  }

  @SuppressWarnings("unchecked")
  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("/list/{collectionId}.json")
  @Operation(
      summary = "List the files of a collection",
      description = "Lists files in a collection"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "URLs returned"),
      @ApiResponse(responseCode = "404", description = "Collection not found")
  })
  public Response restGetCollectionContents(
      @Parameter(description = "the collection identifier", required = true)
      @PathParam("collectionId") String collectionId
  ) throws NotFoundException {
    URI[] uris = super.getCollectionContents(collectionId);
    JsonArray jsonArray = new JsonArray();
    for (URI uri : uris) {
      jsonArray.add(uri.toString());
    }
    return Response.ok(jsonArray.toString()).build();
  }

  @POST
  @Path("/copy/{fromCollection}/{fromFileName}/{toMediaPackage}/{toMediaPackageElement}/{toFileName}")
  @Operation(
      summary = "Copy a file from a collection to a media package",
      description = "Copies a file from a collection to a mediapackage"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "URL returned"),
      @ApiResponse(responseCode = "404", description = "File to copy not found")
  })
  public Response restCopyTo(
      @Parameter(description = "the collection identifier hosting the source", required = true)
      @PathParam("fromCollection") String fromCollection,
      @Parameter(description = "the source file name", required = true)
      @PathParam("fromFileName") String fromFileName,
      @Parameter(description = "the destination mediapackage identifier", required = true)
      @PathParam("toMediaPackage") String toMediaPackage,
      @Parameter(
          description = "the destination mediapackage element identifier",
          required = true
      )
      @PathParam("toMediaPackageElement") String toMediaPackageElement,
      @Parameter(description = "the destination file name", required = true)
      @PathParam("toFileName") String toFileName
  ) throws NotFoundException {
    try {
      URI uri = super.copyTo(fromCollection, fromFileName, toMediaPackage, toMediaPackageElement, toFileName);
      return Response.ok().entity(uri.toString()).build();
    } catch (IOException e) {
      logger.error("Unable to copy file '{}' from collection '{}' to mediapackage {}/{}",
              fromFileName, fromCollection, toMediaPackage, toMediaPackageElement, e);
      return Response.serverError().entity(e.getMessage()).build();
    }
  }

  @POST
  @Path("/move/{fromCollection}/{fromFileName}/{toMediaPackage}/{toMediaPackageElement}/{toFileName}")
  @Operation(
      summary = "Move a file from a collection to a media package",
      description = "Moves a file from a collection to a mediapackage"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "URL returned"),
      @ApiResponse(responseCode = "404", description = "File to move not found")
  })
  public Response restMoveTo(
      @Parameter(description = "the collection identifier hosting the source", required = true)
      @PathParam("fromCollection") String fromCollection,
      @Parameter(description = "the source file name", required = true)
      @PathParam("fromFileName") String fromFileName,
      @Parameter(description = "the destination mediapackage identifier", required = true)
      @PathParam("toMediaPackage") String toMediaPackage,
      @Parameter(
          description = "the destination mediapackage element identifier",
          required = true
      )
      @PathParam("toMediaPackageElement") String toMediaPackageElement,
      @Parameter(description = "the destination file name", required = true)
      @PathParam("toFileName") String toFileName
  ) throws NotFoundException {
    try {
      URI uri = super.moveTo(fromCollection, fromFileName, toMediaPackage, toMediaPackageElement, toFileName);
      return Response.ok().entity(uri.toString()).build();
    } catch (IOException e) {
      logger.error("Unable to move file '{}' from collection '{}' to mediapackage {}/{}",
              fromFileName, fromCollection, toMediaPackage, toMediaPackageElement, e);
      return Response.serverError().entity(e.getMessage()).build();
    }
  }

  @SuppressWarnings("unchecked")
  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("storage")
  @Operation(
      summary = "Get the storage statistics",
      description = "Returns a report on the disk usage and availability"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Report returned")
  })
  public Response restGetTotalStorage() {
    long total = this.getTotalSpace().get();
    long usable = this.getUsableSpace().get();
    long used = this.getUsedSpace().get();
    String summary = this.getDiskSpace();
    JsonObject json = new JsonObject();
    json.addProperty("size", total);
    json.addProperty("usable", usable);
    json.addProperty("used", used);
    json.addProperty("summary", summary);
    return Response.ok(json.toString()).build();
  }

  @GET
  @Produces(MediaType.TEXT_PLAIN)
  @Path("/baseUri")
  @Operation(
      summary = "Get the base URI of the repository",
      description = "Returns a base URI for this repository"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Base URI returned")
  })
  public Response restGetBaseUri() {
    return Response.ok(super.getBaseUri().toString()).build();
  }
}
