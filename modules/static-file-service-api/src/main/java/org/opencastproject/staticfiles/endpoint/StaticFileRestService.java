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

package org.opencastproject.staticfiles.endpoint;


import org.opencastproject.security.api.SecurityService;
import org.opencastproject.staticfiles.api.StaticFileService;
import org.opencastproject.systems.OpencastConstants;
import org.opencastproject.util.MimeTypes;
import org.opencastproject.util.NotFoundException;
import org.opencastproject.util.OsgiUtil;
import org.opencastproject.util.ProgressInputStream;
import org.opencastproject.util.RestUtil;
import org.opencastproject.util.RestUtil.R;
import org.opencastproject.util.UrlSupport;

import org.apache.commons.fileupload.FileItemIterator;
import org.apache.commons.fileupload.FileItemStream;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.BooleanUtils;
import org.osgi.service.cm.ConfigurationException;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
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
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * Stores and serves static files via HTTP.
 */
@Path("/staticfiles")
@Tag(
    name = "Static Resources Service",
    description = "This service allows the uploading of static resources such as videos and images."
)
@Component(
    immediate = true,
    service = StaticFileRestService.class,
    property = {
        "service.description=Static File Service REST Endpoint",
        "opencast.service.type=org.opencastproject.staticfiles",
        "opencast.service.path=/staticfiles",
        "opencast.service.jobproducer=false"
    }
)
@JaxrsResource
public class StaticFileRestService {

  /** The logging facility */
  private static final Logger logger = LoggerFactory.getLogger(StaticFileRestService.class);

  /** The default URL path of the static files */
  public static final String STATICFILES_URL_PATH = "staticfiles";

  /** The key to find whether the static file webserver is enabled or not. */
  public static final String STATICFILES_WEBSERVER_ENABLED_KEY = "org.opencastproject.staticfiles.webserver.enabled";

  /** The key to find the URL for where a webserver is hosting the static files. */
  public static final String STATICFILES_WEBSERVER_URL_KEY = "org.opencastproject.staticfiles.webserver.url";

  /** The key to find the maximum sized file to accept as an upload. */
  public static final String STATICFILES_UPLOAD_MAX_SIZE_KEY = "org.opencastproject.staticfiles.upload.max.size";

  /** The security service */
  private SecurityService securityService = null;

  /** The static file service */
  private StaticFileService staticFileService;

  /** The URL of the current server */
  private String serverUrl;

  /** The URL to serve static files from a webserver instead of Opencast. */
  private Optional<String> webserverURL = Optional.empty();

  /** The maximum file size to allow to be uploaded in bytes, default 1GB */
  private long maxUploadSize = 1000000000;

  /**
   * Whether to provide urls to download the static files from a webserver
   * without organization and security protection, or use Opencast to provide
   * the files.
   */
  protected boolean useWebserver = false;

  /** OSGi callback to bind service instance. */
  @Reference
  public void setStaticFileService(StaticFileService staticFileService) {
    this.staticFileService = staticFileService;
  }

  /** OSGi callback to bind service instance. */
  @Reference
  public void setSecurityService(SecurityService securityService) {
    this.securityService = securityService;
  }

  /**
   * OSGI callback for activating this component
   *
   * @param cc
   *          the osgi component context
   */
  public void activate(ComponentContext cc) throws ConfigurationException {
    logger.info("Static File REST Service started.");
    serverUrl = OsgiUtil.getContextProperty(cc, OpencastConstants.SERVER_URL_PROPERTY);
    useWebserver = BooleanUtils.toBoolean(OsgiUtil.getOptCfg(cc.getProperties(), STATICFILES_WEBSERVER_ENABLED_KEY)
            .orElse("false"));
    webserverURL = OsgiUtil.getOptCfg(cc.getProperties(), STATICFILES_WEBSERVER_URL_KEY);

    Optional<String> cfgMaxUploadSize = OsgiUtil.getOptContextProperty(cc, STATICFILES_UPLOAD_MAX_SIZE_KEY);
    if (cfgMaxUploadSize.isPresent()) {
      maxUploadSize = Long.parseLong(cfgMaxUploadSize.get());
    }
  }

  @GET
  @Path("{uuid}")
  @Operation(
      summary = "Get a static file",
      description = "Returns a static file resource"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returns a static file resource"),
      @ApiResponse(responseCode = "404", description = "No file by the given uuid found")
  })
  public Response getStaticFile(
      @Parameter(description = "Static File Universal Unique Id", required = true)
      @PathParam("uuid") String uuid
  ) throws NotFoundException {
    try {
      final InputStream file = staticFileService.getFile(uuid);
      final String filename = staticFileService.getFileName(uuid);
      final Long length = staticFileService.getContentLength(uuid);
      // It is safe to pass the InputStream without closing it, JAX-RS takes care of that
      return RestUtil.R.ok(file, getMimeType(filename), Optional.of(length), Optional.of(filename));
    } catch (NotFoundException | IOException e) {
      return RestUtil.R.notFound();
    }
  }

  @POST
  @Consumes(MediaType.MULTIPART_FORM_DATA)
  @Produces(MediaType.TEXT_PLAIN)
  @Path("")
  @Operation(
      summary = "Upload a static file",
      description = "Post a new static resource"
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
                          description = "The static resource file"
                      )
                  )
              }
          )
      }
  )
  @ApiResponses({
      @ApiResponse(responseCode = "201", description = "Returns the id of the uploaded static resource"),
      @ApiResponse(
          responseCode = "400",
          description = "No filename or file to upload found, or the upload size is too big"
      )
  })
  public Response postStaticFile(
      @Context HttpServletRequest request
  ) {
    if (maxUploadSize > 0 && request.getContentLength() > maxUploadSize) {
      logger.warn("Preventing upload of static file as its size {} is larger than the max size allowed {}",
              request.getContentLength(), maxUploadSize);
      return Response.status(Status.BAD_REQUEST).build();
    }
    ProgressInputStream inputStream = null;
    try {
      String filename = null;
      if (ServletFileUpload.isMultipartContent(request)) {
        boolean isDone = false;
        for (FileItemIterator iter = new ServletFileUpload().getItemIterator(request); iter.hasNext();) {
          FileItemStream item = iter.next();
          if (item.isFormField()) {
            continue;
          } else {
            logger.debug("Processing file item");
            filename = item.getName();
            inputStream = new ProgressInputStream(item.openStream());
            inputStream.addPropertyChangeListener(new PropertyChangeListener() {
              @Override
              public void propertyChange(PropertyChangeEvent evt) {
                long totalNumBytesRead = (Long) evt.getNewValue();
                if (totalNumBytesRead > maxUploadSize) {
                  logger.warn("Upload limit of {} bytes reached, returning a bad request.", maxUploadSize);
                  throw new WebApplicationException(Status.BAD_REQUEST);
                }
              }
            });
            isDone = true;
          }
          if (isDone) {
            break;
          }
        }
      } else {
        logger.warn("Request is not multi part request, returning a bad request.");
        return Response.status(Status.BAD_REQUEST).build();
      }

      if (filename == null) {
        logger.warn("Request was missing the filename, returning a bad request.");
        return Response.status(Status.BAD_REQUEST).build();
      }

      if (inputStream == null) {
        logger.warn("Request was missing the file, returning a bad request.");
        return Response.status(Status.BAD_REQUEST).build();
      }

      String uuid = staticFileService.storeFile(filename, inputStream);
      try {
        return Response.created(getStaticFileURL(uuid)).entity(uuid).build();
      } catch (NotFoundException e) {
        logger.error("Previous stored file with uuid {} couldn't beren found:", uuid, e);
        return Response.serverError().build();
      }
    } catch (WebApplicationException e) {
      return e.getResponse();
    } catch (Exception e) {
      logger.error("Unable to store file", e);
      return Response.serverError().build();
    } finally {
      IOUtils.closeQuietly(inputStream);
    }
  }

  @POST
  @Path("{uuid}/persist")
  @Operation(
      summary = "Persist an uploaded static file",
      description = "Persists a recently uploaded file to the permanent storage"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The file has been persisted"),
      @ApiResponse(responseCode = "404", description = "No file by the given UUID found")
  })
  public Response persistFile(
      @Parameter(description = "File UUID", required = true)
      @PathParam("uuid") String uuid
  ) throws NotFoundException {
    try {
      staticFileService.persistFile(uuid);
      return R.ok();
    } catch (IOException e) {
      logger.error("Unable to persist file '{}':", uuid, e);
      return R.serverError();
    }
  }

  @GET
  @Produces(MediaType.TEXT_PLAIN)
  @Path("{uuid}/url")
  @Operation(
      summary = "Get the URL of a static file",
      description = "Returns a static file resource's URL"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returns a static file resource's URL"),
      @ApiResponse(responseCode = "404", description = "No file by the given uuid found")
  })
  public Response getStaticFileUrl(
      @Parameter(description = "Static File Universal Unique Id", required = true)
      @PathParam("uuid") String uuid
  ) throws NotFoundException {
    try {
      return Response.ok(getStaticFileURL(uuid).toString()).build();
    } catch (NotFoundException e) {
      throw e;
    } catch (Exception e) {
      logger.error("Unable to retrieve static file URL from {}", uuid, e);
      return Response.serverError().build();
    }
  }

  @DELETE
  @Path("{uuid}")
  @Operation(
      summary = "Delete a static file",
      description = "Remove the static file"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "File deleted"),
      @ApiResponse(responseCode = "404", description = "No file by the given uuid found")
  })
  public Response deleteStaticFile(
      @Parameter(description = "Static File Universal Unique Id", required = true)
      @PathParam("uuid") String uuid
  ) throws NotFoundException {
    try {
      staticFileService.deleteFile(uuid);
      return Response.noContent().build();
    } catch (NotFoundException e) {
      throw e;
    } catch (Exception e) {
      logger.error("Unable to delete static file {}", uuid, e);
      return Response.serverError().build();
    }
  }

  /**
   * Get the URI for a static file resource depending on whether to get it
   * direct from Opencast or from a webserver.
   *
   * @param uuid
   *          The unique identifier for the static file.
   * @return The URL for the static file resource.
   * @throws NotFoundException
   *           if the resource couldn't been found
   */
  public URI getStaticFileURL(String uuid) throws NotFoundException {
    if (useWebserver && webserverURL.isPresent()) {
      return URI.create(UrlSupport.concat(webserverURL.get(), securityService.getOrganization().getId(), uuid,
              staticFileService.getFileName(uuid)));
    } else {
      return URI.create(UrlSupport.concat(serverUrl, STATICFILES_URL_PATH, uuid));
    }
  }

  private Optional<String> getMimeType(final String filename) {
    Optional<String> mimeType;
    try {
      mimeType = Optional.of(MimeTypes.fromString(filename).toString());
    } catch (Exception e) {
      logger.warn("Unable to detect the mime type of file {}", filename);
      mimeType = Optional.<String> empty();
    }
    return mimeType;
  }

}
