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

package org.opencastproject.assetmanager.aws.s3.endpoint;

import static org.opencastproject.util.RestUtil.R.noContent;
import static org.opencastproject.util.RestUtil.R.notFound;
import static org.opencastproject.util.RestUtil.R.ok;

import org.opencastproject.assetmanager.api.AssetManager;
import org.opencastproject.assetmanager.api.AssetManagerException;
import org.opencastproject.assetmanager.api.Snapshot;
import org.opencastproject.assetmanager.api.storage.AssetStoreException;
import org.opencastproject.assetmanager.api.storage.StoragePath;
import org.opencastproject.assetmanager.aws.s3.AwsS3AssetStore;
import org.opencastproject.mediapackage.MediaPackageElement;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.util.NotFoundException;

import com.amazonaws.services.s3.model.StorageClass;

import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;
import java.util.function.Supplier;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

@Path("/assets/aws/s3")
@Tag(
    name = "AWS S3 Archive",
    description = "This service handles AWS S3 archived assets"
)
@Component(
    immediate = true,
    service = AwsS3RestEndpoint.class,
    property = {
        "service.description=AssetManager S3 REST Endpoint",
        "opencast.service.type=org.opencastproject.assetmanager.aws-s3",
        "opencast.service.path=/assets/aws/s3",
    }
)
@JaxrsResource
public class AwsS3RestEndpoint {

  private static final Logger logger = LoggerFactory.getLogger(AwsS3RestEndpoint.class);

  private AwsS3AssetStore awsS3AssetStore = null;
  private AssetManager assetManager = null;
  private SecurityService securityService = null;

  @GET
  @Path("{mediaPackageId}/assets/storageClass")
  @Produces(MediaType.TEXT_PLAIN)
  @Operation(
      summary = "Get the S3 storage class of the assets of a media package",
      description = "Get the S3 Storage Class for each asset in the Media Package"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "mediapackage found in S3"),
      @ApiResponse(responseCode = "401", description = "The user is not authorized to access the media package"),
      @ApiResponse(responseCode = "404", description = "mediapackage not found or has no assets in S3"),
      @ApiResponse(responseCode = "500", description = "An error occurred while accessing the assets")
  })
  public Response getStorageClass(
      @Parameter(description = "The media package indentifier.", required = true)
      @PathParam("mediaPackageId") final String mediaPackageId
  ) {
    return handleException(() -> {
      String mpId = StringUtils.trimToNull(mediaPackageId);

      Optional<Snapshot> snapshot = assetManager.getLatestSnapshot(mpId);
      if (snapshot.isEmpty()) {
        return notFound();
      }

      StringBuilder info = new StringBuilder();
      for (MediaPackageElement e : snapshot.get().getMediaPackage().elements()) {
        if (e.getElementType() == MediaPackageElement.Type.Publication) {
          continue;
        }

        StoragePath storagePath = new StoragePath(securityService.getOrganization().getId(),
            mpId,
            snapshot.get().getVersion(),
            e.getIdentifier());
        if (awsS3AssetStore.contains(storagePath)) {
          try {
            info.append(String.format("%s,%s\n", awsS3AssetStore.getAssetObjectKey(storagePath),
                                                 awsS3AssetStore.getAssetStorageClass(storagePath)));
          } catch (AssetStoreException ex) {
            throw new AssetManagerException(ex);
          }
        } else {
          info.append(String.format("%s,NONE\n", e.getURI()));
        }
      }
      return ok(info.toString());
    });
  }

  @PUT
  @Path("{mediaPackageId}/assets")
  @Produces(MediaType.TEXT_PLAIN)
  @Operation(
      summary = "Change the S3 storage class of the assets of a media package",
      description = "Move the Media Package assets to the specified S3 Storage Class if possible"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "mediapackage found in S3"),
      @ApiResponse(responseCode = "401", description = "The user is not authorized to access the media package"),
      @ApiResponse(responseCode = "404", description = "mediapackage not found or has no assets in S3"),
      @ApiResponse(responseCode = "500", description = "An error occurred while accessing the assets")
  })
  public Response modifyStorageClass(
      @Parameter(description = "The media package indentifier.", required = true)
      @PathParam("mediaPackageId") final String mediaPackageId,
      @Parameter(
          description = "The S3 storage class, valid terms STANDARD, STANDARD_IA, INTELLIGENT_TIERING, ONEZONE_IA,"
              + "GLACIER_IR, GLACIER, and DEEP_ARCHIVE. See https://aws.amazon.com/s3/storage-classes/",
          required = true
      )
      @FormParam("storageClass") final String storageClass
  ) {
    return handleException(() -> {
      String mpId = StringUtils.trimToNull(mediaPackageId);
      String sc = StringUtils.trimToNull(storageClass);

      Optional<Snapshot> snapshot = assetManager.getLatestSnapshot(mpId);
      if (snapshot.isEmpty()) {
        return notFound();
      }
      StringBuilder info = new StringBuilder();
      for (MediaPackageElement e : snapshot.get().getMediaPackage().elements()) {
        if (e.getElementType() == MediaPackageElement.Type.Publication) {
          continue;
        }

        StoragePath storagePath = new StoragePath(securityService.getOrganization().getId(),
            mpId,
            snapshot.get().getVersion(),
            e.getIdentifier());
        if (awsS3AssetStore.contains(storagePath)) {
          try {
            info.append(String.format("%s,%s\n", awsS3AssetStore.getAssetObjectKey(storagePath),
                                                 awsS3AssetStore.modifyAssetStorageClass(storagePath, sc)));
          } catch (AssetStoreException ex) {
            throw new AssetManagerException(ex);
          }
        } else {
          info.append(String.format("%s,NONE\n", e.getURI()));
        }
      }
      return ok(info.toString());
    });
  }

  @GET
  @Path("glacier/{mediaPackageId}/assets")
  @Produces(MediaType.TEXT_PLAIN)
  @Operation(
      summary = "Get the restore status of the assets of a media package",
      description = "Get the mediapackage asset's restored status"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "mediapackage found in S3 and assets in Glacier"),
      @ApiResponse(responseCode = "204", description = "mediapackage found in S3 but no assets in Glacier"),
      @ApiResponse(responseCode = "401", description = "The user is not authorized to access the media package"),
      @ApiResponse(responseCode = "404", description = "mediapackage not found or has no assets in S3"),
      @ApiResponse(responseCode = "500", description = "An error occurred while accessing the assets")
  })
  public Response getAssetRestoreState(
      @Parameter(description = "The media package indentifier.", required = true)
      @PathParam("mediaPackageId") final String mediaPackageId
  ) {
    return handleException(() -> {
      String mpId = StringUtils.trimToNull(mediaPackageId);

      Optional<Snapshot> snapshot = assetManager.getLatestSnapshot(mpId);
      if (snapshot.isEmpty()) {
        return notFound();
      }

      StringBuilder info = new StringBuilder();
      for (MediaPackageElement e : snapshot.get().getMediaPackage().elements()) {
        if (e.getElementType() == MediaPackageElement.Type.Publication) {
          continue;
        }

        StoragePath storagePath = new StoragePath(securityService.getOrganization().getId(),
                                                  mpId,
                                                  snapshot.get().getVersion(),
                                                  e.getIdentifier());
        if (isFrozen(storagePath)) {
          try {
            info.append(String.format("%s,%s\n", awsS3AssetStore.getAssetObjectKey(storagePath),
                                                 awsS3AssetStore.getAssetRestoreStatusString(storagePath)));
          } catch (AssetStoreException ex) {
            throw new AssetManagerException(ex);
          }
        } else {
          info.append(String.format("%s,NONE\n", storagePath));
        }
      }
      if (info.length() == 0) {
        return noContent();
      }
      return ok(info.toString());
    });
  }

  @PUT
  @Path("glacier/{mediaPackageId}/assets")
  @Produces(MediaType.TEXT_PLAIN)
  @Operation(
      summary = "Restore the assets of a media package from Glacier",
      description = "Initiate the restore of any assets in Glacier storage class"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "restore of assets started"),
      @ApiResponse(responseCode = "400", description = "The restore period is not greater than zero"),
      @ApiResponse(responseCode = "401", description = "The user is not authorized to access the media package"),
      @ApiResponse(responseCode = "404", description = "mediapackage not found or has no assets in S3"),
      @ApiResponse(responseCode = "500", description = "An error occurred while restoring the assets")
  })
  public Response restoreAssets(
      @Parameter(description = "The media package indentifier.", required = true)
      @PathParam("mediaPackageId") final String mediaPackageId,
      @Parameter(
          description = "Number of days to restore the assets for, default see service configuration",
          schema = @Schema(example = "2")
      )
      @FormParam("restorePeriod") final Integer restorePeriod
  ) {
    return handleException(() -> {
      String mpId = StringUtils.trimToNull(mediaPackageId);
      Integer rp = restorePeriod != null ? restorePeriod : awsS3AssetStore.getRestorePeriod();

      if (rp < 1) {
        throw new BadRequestException("Restore period must be greater than zero!");
      }

      Optional<Snapshot> snapshot = assetManager.getLatestSnapshot(mpId);
      if (snapshot.isEmpty()) {
        return notFound();
      }

      for (MediaPackageElement e : snapshot.get().getMediaPackage().elements()) {
        if (e.getElementType() == MediaPackageElement.Type.Publication) {
          continue;
        }

        StoragePath storagePath = new StoragePath(securityService.getOrganization().getId(),
                                                  mpId,
                                                  snapshot.get().getVersion(),
                                                  e.getIdentifier());
        if (isFrozen(storagePath)) {
          try {
            // Initiate restore and return
            awsS3AssetStore.initiateRestoreAsset(storagePath, rp);
          } catch (AssetStoreException ex) {
            throw new AssetManagerException(ex);
          }
        }
      }
      return noContent();
    });
  }

  private boolean isFrozen(StoragePath storagePath) {
    String assetStorageClass = awsS3AssetStore.getAssetStorageClass(storagePath);
    return awsS3AssetStore.contains(storagePath)
        && (StorageClass.Glacier == StorageClass.fromValue(assetStorageClass)
          || StorageClass.DeepArchive == StorageClass.fromValue(assetStorageClass));
  }


  /** Unify exception handling. */
  public static <A> A handleException(Supplier<A> f) {
    try {
      return f.get();
    } catch (AssetManagerException e) {
      if (e.isCauseNotAuthorized()) {
        throw new WebApplicationException(e, Response.Status.UNAUTHORIZED);
      }
      if (e.isCauseNotFound()) {
        throw new WebApplicationException(e, Response.Status.NOT_FOUND);
      }
      throw new WebApplicationException(e, Response.Status.INTERNAL_SERVER_ERROR);
    } catch (WebApplicationException e) {
      throw e;
    } catch (Exception e) {
      logger.error("Error calling archive REST method", e);
      if (e instanceof NotFoundException) {
        throw new WebApplicationException(e, Response.Status.NOT_FOUND);
      }
      throw new WebApplicationException(e, Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  @Reference()
  void setAwsS3AssetStore(AwsS3AssetStore store) {
    awsS3AssetStore = store;
  }

  @Reference()
  void setAssetManager(AssetManager service) {
    assetManager = service;
  }

  @Reference()
  void setSecurityService(SecurityService service) {
    securityService = service;
  }
}
