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
package org.opencastproject.assetmanager.impl.endpoint;

import static org.opencastproject.assetmanager.api.AssetManager.DEFAULT_OWNER;
import static org.opencastproject.systems.OpencastConstants.WORKFLOW_PROPERTIES_NAMESPACE;
import static org.opencastproject.util.RestUtil.R.badRequest;
import static org.opencastproject.util.RestUtil.R.forbidden;
import static org.opencastproject.util.RestUtil.R.noContent;
import static org.opencastproject.util.RestUtil.R.notFound;
import static org.opencastproject.util.RestUtil.R.ok;

import org.opencastproject.assetmanager.api.AssetManager;
import org.opencastproject.assetmanager.api.Property;
import org.opencastproject.assetmanager.api.PropertyId;
import org.opencastproject.assetmanager.api.Value;
import org.opencastproject.mediapackage.MediaPackage;
import org.opencastproject.mediapackage.MediaPackageImpl;
import org.opencastproject.mediapackage.MediaPackageSupport;
import org.opencastproject.rest.AbstractJobProducerEndpoint;
import org.opencastproject.security.api.UnauthorizedException;
import org.opencastproject.util.Checksum;
import org.opencastproject.util.ChecksumType;
import org.opencastproject.util.NotFoundException;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import javax.ws.rs.DELETE;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * A base REST endpoint for the {@link AssetManager}.
 * <p>
 * The endpoint provides assets over http (see {@link org.opencastproject.assetmanager.impl.HttpAssetProvider}).
 * <p>
 * No @Path annotation here since this class cannot be created by JAX-RS. Put it on the concrete implementations.
 */
@Tag(
    name = "AssetManager",
    description = "This service indexes and queries available (distributed) episodes."
)
public abstract class AbstractAssetManagerRestEndpoint extends AbstractJobProducerEndpoint {
  protected static final Logger logger = LoggerFactory.getLogger(AbstractAssetManagerRestEndpoint.class);

  private final Gson gson = new Gson();

  private final java.lang.reflect.Type stringMapType = new TypeToken<Map<String, String>>() { }.getType();

  public abstract AssetManager getAssetManager();

  /**
   * @deprecated use {@link #snapshot} instead
   */
  @POST
  @Path("add")
  @Operation(
      summary = "Add a media package (deprecated)",
      description = "Adds a media package to the asset manager. This method is deprecated in "
          + "favor of method POST 'snapshot'."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "The media package was added, no content to return."),
      @ApiResponse(responseCode = "403", description = "Not allowed to add a media package."),
      @ApiResponse(
          responseCode = "500",
          description = "There has been an internal error and the media package could not be added"
      )
  })
  @Deprecated
  public Response add(
      @Parameter(
          description = "The media package to add, as XML.",
          required = true,
          schema = @Schema(type = "string")
      )
      @FormParam("mediapackage") final MediaPackageImpl mediaPackage
  ) {
    return snapshot(mediaPackage);
  }

  @POST
  @Path("snapshot")
  @Operation(
      summary = "Take a snapshot of a media package",
      description = "Take a versioned snapshot of a media package."
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "204",
          description = "A snapshot of the media package has been taken, no content to return."
      ),
      @ApiResponse(responseCode = "403", description = "Not allowed to take a snapshot."),
      @ApiResponse(
          responseCode = "500",
          description = "There has been an internal error and no snapshot could be taken."
      )
  })
  public Response snapshot(
      @Parameter(
          description = "The media package to take a snapshot from, as XML.",
          required = true,
          schema = @Schema(type = "string")
      )
      @FormParam("mediapackage") final MediaPackageImpl mediaPackage
  ) {
    if (mediaPackage == null) {
      return badRequest("Missing mediapackage");
    }
    // The form parameter is converted by JAX-RS through MediaPackageImpl.valueOf(String),
    // which already validates the identifiers; repeat the check here so the endpoint stays
    // safe even if the conversion path ever changes.
    try {
      MediaPackageSupport.checkPathSafety(mediaPackage);
    } catch (IllegalArgumentException e) {
      logger.warn("Rejected snapshot: invalid mediapackage identifiers", e);
      return badRequest("Invalid mediapackage identifiers");
    }
    try {
      getAssetManager().takeSnapshot(DEFAULT_OWNER, mediaPackage);
      return noContent();
    } catch (Exception e) {
      return handleException(e);
    }
  }

  @POST
  @Path("updateIndex")
  @Operation(
      summary = "Update the search index of an event",
      description = "Trigger search index update for event. The usage of this is limited to global administrators."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "Update successfully triggered."),
      @ApiResponse(responseCode = "403", description = "Not allowed to trigger update."),
      @ApiResponse(responseCode = "404", description = "No such event found.")
  })
  public Response indexUpdate(
      @Parameter(description = "The event ID to trigger an index update for.", required = true)
      @FormParam("id") final String id
  ) {
    try {
      getAssetManager().triggerIndexUpdate(id);
      return noContent();
    } catch (UnauthorizedException e) {
      return forbidden();
    } catch (NotFoundException e) {
      return notFound();
    } catch (Exception e) {
      return handleException(e);
    }
  }

  @DELETE
  @Path("delete/{id}")
  @Operation(
      summary = "Delete the snapshots of an episode",
      description = "Removes snapshots of an episode, owned by the default owner from the asset manager."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "Snapshots have been removed, no content to return."),
      @ApiResponse(
          responseCode = "404",
          description = "The episode does either not exist or no snapshots are owned by the default owner."
      ),
      @ApiResponse(responseCode = "403", description = "Not allowed to delete this episode."),
      @ApiResponse(
          responseCode = "500",
          description = "There has been an internal error and the episode could not be deleted."
      )
  })
  public Response delete(
      @Parameter(
          description = "The media package ID of the episode whose snapshots shall be removed"
              + " from the asset manager.",
          required = true
      )
      @PathParam("id") final String mediaPackageId
  ) {
    if (StringUtils.isEmpty(mediaPackageId)) {
      return notFound();
    }
    try {
      if (getAssetManager().deleteSnapshots(mediaPackageId) > 0) {
        return noContent();
      }
      return notFound();
    } catch (Exception e) {
      return handleException(e);
    }
  }

  @GET
  @Produces(MediaType.TEXT_XML)
  @Path("episode/{mediaPackageID}")
  @Operation(
      summary = "Get the latest media package of an episode",
      description = "Get the media package from the last snapshot of an episode."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Media package returned"),
      @ApiResponse(responseCode = "404", description = "Not found"),
      @ApiResponse(responseCode = "403", description = "Not allowed to read media package."),
      @ApiResponse(responseCode = "500", description = "There has been an internal error.")
  })
  public Response getMediaPackage(
      @Parameter(description = "the media package ID", required = true)
      @PathParam("mediaPackageID") final String mediaPackageId
  ) {

    try {
      Optional<MediaPackage> mp = getAssetManager().getMediaPackage(mediaPackageId);

      if (mp.isPresent()) {
        return ok(mp.get());
      } else {
        return notFound();
      }
    } catch (Exception e) {
      return handleException(e);
    }
  }

  @GET
  @Path("assets/{mediaPackageID}/{mediaPackageElementID}/{version}/{filename}")
  @Operation(
      summary = "Get an asset",
      description = "Get an asset"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "File returned"),
      @ApiResponse(responseCode = "404", description = "Not found"),
      @ApiResponse(responseCode = "304", description = "If file not modified"),
      @ApiResponse(responseCode = "403", description = "Not allowed to read assets of this snapshot."),
      @ApiResponse(responseCode = "500", description = "There has been an internal error.")
  })
  public Response getAsset(
      @Parameter(description = "the media package identifier", required = true)
      @PathParam("mediaPackageID") final String mediaPackageID,
      @Parameter(description = "the media package element identifier", required = true)
      @PathParam("mediaPackageElementID") final String mediaPackageElementID,
      @Parameter(description = "the media package version", required = true)
      @PathParam("version") final String version,
      @Parameter(description = "a descriptive filename used as the download filename", required = true)
      @PathParam("filename") String fileName,
      @Parameter(description = "The digest of the file the client already has. If it matches, 304 is returned")
      @HeaderParam("If-None-Match") String ifNoneMatch
  ) {

    try {
      final var v = getAssetManager().toVersion(version);
      if (v.isPresent()) {
        var assetOpt = getAssetManager().getAsset(v.get(), mediaPackageID, mediaPackageElementID);
        if (assetOpt.isPresent()) {
          var asset = assetOpt.get();

          if (StringUtils.isNotBlank(ifNoneMatch)) {
            Checksum checksum = asset.getChecksum();

            if (checksum != null && checksum.getType().equals(ChecksumType.DEFAULT_TYPE)) {
              String md5 = checksum.getValue();

              if (md5.equals(ifNoneMatch)) {
                return Response.notModified(md5).build();
              }
            }
            else {
              logger.warn("Checksum of asset {} of media package {} is of incorrect type or missing",
                      mediaPackageElementID, mediaPackageID);
            }
          }

          if (StringUtils.isBlank(fileName)) {
            String suffix = "unknown";
            if (asset.getMimeType().isPresent()) {
              var mimetype = asset.getMimeType().get();
              if (mimetype.getSuffix().isPresent()) {
                suffix = mimetype.getSuffix().get();
              }
            }
            fileName = mediaPackageElementID
                .concat(".")
                .concat(suffix);
          }

          // Write the file contents back
          Optional<Long> length = asset.getSize() > 0 ? Optional.of(asset.getSize()) : Optional.empty();
          return ok(asset.getInputStream(),
                  asset.getMimeType().isPresent()
                      ? Optional.of(asset.getMimeType().get().toString())
                      : Optional.empty(),
                  length,
                  Optional.of(fileName));
        }
        // none
        return notFound();
      }
      // cannot parse version
      return badRequest("malformed version");
    } catch (Exception e) {
      return handleException(e);
    }
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("{mediaPackageID}/properties.json")
  @Operation(
      summary = "Get the properties of an episode",
      description = "Get stored properties for an episode."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Media package returned"),
      @ApiResponse(responseCode = "404", description = "Not found"),
      @ApiResponse(responseCode = "403", description = "Not allowed to read media package."),
      @ApiResponse(responseCode = "500", description = "There has been an internal error.")
  })
  public Response getProperties(
      @Parameter(description = "the media package ID", required = true)
      @PathParam("mediaPackageID") final String mediaPackageId,
      @Parameter(description = "property namespace")
      @QueryParam("namespace") final String namespace
  ) {
    try {
      getAssetManager().selectProperties(mediaPackageId, namespace);

      // build map from properties
      HashMap<String, HashMap<String, String>> properties = new HashMap<>();
      for (final Property property : getAssetManager().selectProperties(mediaPackageId, namespace)) {
        final String key = property.getId().getNamespace() + "." + property.getId().getName();
        final HashMap<String, String> val = new HashMap<>();
        val.put("type", property.getValue().getType().getClass().getSimpleName());
        val.put("value", property.getValue().get().toString());
        properties.put(key, val);
      }
      return ok(gson.toJson(properties));
    } catch (Exception e) {
      return handleException(e);
    }
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("{mediaPackageID}/workflowProperties.json")
  @Operation(
      summary = "Get the workflow properties of an episode",
      description = "Get stored workflow properties for an episode."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The workflow properties as JSON"),
      @ApiResponse(responseCode = "404", description = "Not found"),
      @ApiResponse(responseCode = "403", description = "Not allowed to read media package."),
      @ApiResponse(responseCode = "500", description = "There has been an internal error.")
  })
  public Response getWorkflowProperties(
      @Parameter(description = "the media package ID", required = true)
      @PathParam("mediaPackageID") final String mediaPackageId
  ) {
    try {
      // build map from properties
      HashMap<String, String> properties = new HashMap<>();
      for (final Property property
          : getAssetManager().selectProperties(mediaPackageId, WORKFLOW_PROPERTIES_NAMESPACE)) {
        properties.put(property.getId().getName(), property.getValue().get(Value.STRING));
      }
      return ok(gson.toJson(properties));
    } catch (Exception e) {
      return handleException(e);
    }
  }


  @POST
  @Path("{mediaPackageID}/workflowProperties")
  @Operation(
      summary = "Set the workflow properties of an episode",
      description = "Set additional workflow properties"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "201", description = "Properties successfully set"),
      @ApiResponse(responseCode = "400", description = "Invalid data"),
      @ApiResponse(responseCode = "500", description = "Internal error")
  })
  public Response setWorkflowProperties(
      @Parameter(description = "the media package ID", required = true)
      @PathParam("mediaPackageID") final String mediaPackageId,
      @Parameter(description = "JSON object containing new properties", required = true)
      @FormParam("properties") final String propertiesJSON
  ) {
    Map<String, String> properties;
    try {
      properties = gson.fromJson(propertiesJSON, stringMapType);
    } catch (Exception e) {
      return badRequest();
    }
    for (final Map.Entry<String, String> entry : properties.entrySet()) {
      // A null value would persist a Property row with every value column null, which then throws on every
      // later read of that property, so entries without a value are skipped rather than stored.
      if (entry.getValue() == null) {
        continue;
      }
      final PropertyId propertyId = PropertyId.mk(mediaPackageId, WORKFLOW_PROPERTIES_NAMESPACE, entry.getKey());
      final Property property = Property.mk(propertyId, Value.mk(entry.getValue()));
      if (!getAssetManager().setProperty(property)) {
        return notFound();
      }
    }
    return noContent();
  }

  /** Unify exception handling. */
  public static Response handleException(Exception e) {
    logger.debug("Error calling REST method", e);
    Throwable cause = e;
    if (e.getCause() != null) {
      cause = e.getCause();
    }
    if (cause instanceof UnauthorizedException) {
      return forbidden();
    }

    throw new WebApplicationException(e, Response.Status.INTERNAL_SERVER_ERROR);
  }
}
