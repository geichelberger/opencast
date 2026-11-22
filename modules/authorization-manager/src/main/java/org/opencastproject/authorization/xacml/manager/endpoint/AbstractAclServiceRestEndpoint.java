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

package org.opencastproject.authorization.xacml.manager.endpoint;

import static org.opencastproject.util.RestUtil.R.conflict;
import static org.opencastproject.util.RestUtil.R.noContent;
import static org.opencastproject.util.RestUtil.R.notFound;
import static org.opencastproject.util.RestUtil.R.ok;
import static org.opencastproject.util.RestUtil.R.serverError;

import org.opencastproject.assetmanager.api.AssetManager;
import org.opencastproject.authorization.xacml.manager.api.AclService;
import org.opencastproject.authorization.xacml.manager.api.AclServiceException;
import org.opencastproject.authorization.xacml.manager.api.AclServiceFactory;
import org.opencastproject.authorization.xacml.manager.api.ManagedAcl;
import org.opencastproject.authorization.xacml.manager.impl.ManagedAclImpl;
import org.opencastproject.mediapackage.MediaPackage;
import org.opencastproject.mediapackage.MediaPackageException;
import org.opencastproject.security.api.AccessControlList;
import org.opencastproject.security.api.AccessControlParser;
import org.opencastproject.security.api.AccessControlUtil;
import org.opencastproject.security.api.AclScope;
import org.opencastproject.security.api.AuthorizationService;
import org.opencastproject.security.api.Organization;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.util.NotFoundException;

import com.google.gson.JsonArray;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

import javax.ws.rs.DELETE;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;

public abstract class AbstractAclServiceRestEndpoint {
  private static final Logger logger = LoggerFactory.getLogger(AbstractAclServiceRestEndpoint.class);

  protected abstract AclServiceFactory getAclServiceFactory();

  protected abstract SecurityService getSecurityService();

  protected abstract AssetManager getAssetManager();

  protected abstract AuthorizationService getAuthorizationService();

  @GET
  @Path("/acl/{aclId}")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get an ACL",
      description = "Return the ACL by the given id"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The ACL has successfully been returned"),
      @ApiResponse(responseCode = "404", description = "The ACL has not been found"),
      @ApiResponse(responseCode = "500", description = "Error during returning the ACL")
  })
  public String getAcl(
      @Parameter(description = "The ACL identifier", required = true)
      @PathParam("aclId") long aclId
  ) throws NotFoundException {
    final Optional<ManagedAcl> managedAcl = aclService().getAcl(aclId);
    if (managedAcl.isEmpty()) {
      logger.info("No ACL with id '{}' could be found", aclId);
      throw new NotFoundException();
    }
    return JsonConv.full(managedAcl.get()).toString();
  }

  @POST
  @Path("/acl/extend")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Add a role and action to an ACL",
      description = "Return the given ACL with a new role and action in JSON format"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The ACL has successfully been returned"),
      @ApiResponse(responseCode = "400", description = "The ACL, action or role was invalid or empty"),
      @ApiResponse(responseCode = "500", description = "Error during returning the ACL")
  })
  public String extendAcl(
      @Parameter(description = "The access control list", required = true)
      @FormParam("acl") String accessControlList,
      @Parameter(description = "The action for the ACL", required = true)
      @FormParam("action") String action,
      @Parameter(description = "The role for the ACL", required = true)
      @FormParam("role") String role,
      @Parameter(description = "The allow status for the ACL", required = true)
      @FormParam("allow") boolean allow
  ) {
    if (StringUtils.isBlank(accessControlList) || StringUtils.isBlank(action) || StringUtils.isBlank(role)) {
      throw new WebApplicationException(Response.Status.BAD_REQUEST);
    }

    AccessControlList acl = AccessControlUtil.extendAcl(parseAcl(accessControlList), role, action, allow);
    return JsonConv.full(acl).toString();
  }

  @POST
  @Path("/acl/reduce")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Remove a role and action from an ACL",
      description = "Return the given ACL without a role and action in JSON format"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The ACL has successfully been returned"),
      @ApiResponse(responseCode = "400", description = "The ACL, role or action was invalid or empty"),
      @ApiResponse(responseCode = "500", description = "Error during returning the ACL")
  })
  public String reduceAcl(
      @Parameter(description = "The access control list", required = true)
      @FormParam("acl") String accessControlList,
      @Parameter(description = "The action for the ACL", required = true)
      @FormParam("action") String action,
      @Parameter(description = "The role for the ACL", required = true)
      @FormParam("role") String role
  ) {
    if (StringUtils.isBlank(accessControlList) || StringUtils.isBlank(action) || StringUtils.isBlank(role)) {
      throw new WebApplicationException(Response.Status.BAD_REQUEST);
    }

    AccessControlList acl = AccessControlUtil.reduceAcl(parseAcl(accessControlList), role, action);
    return JsonConv.full(acl).toString();
  }

  @GET
  @Path("/acl/acls.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "List the ACLs",
      description = "Lists the ACL's as JSON"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The list of ACL's has successfully been returned"),
      @ApiResponse(responseCode = "500", description = "Error during returning the list of ACL's")
  })
  public String getAcls() {
    JsonArray acls = new JsonArray();
    aclService().getAcls().stream()
        .map(JsonConv.fullManagedAcl)
        .forEach(acls::add);
    return acls.toString();
  }

  @POST
  @Path("/acl")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Create an ACL",
      description = "Create an ACL"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The ACL has successfully been added"),
      @ApiResponse(responseCode = "409", description = "An ACL with the same name already exists"),
      @ApiResponse(responseCode = "400", description = "Unable to parse the ACL"),
      @ApiResponse(responseCode = "500", description = "Error during adding the ACL")
  })
  public String createAcl(
      @Parameter(description = "The ACL name", required = true)
      @FormParam("name") String name,
      @Parameter(description = "The access control list", required = true)
      @FormParam("acl") String accessControlList
  ) {
    final AccessControlList acl = parseAcl(accessControlList);
    final Optional<ManagedAcl> managedAcl = aclService().createAcl(acl, name);
    if (managedAcl.isEmpty()) {
      logger.info("An ACL with the same name '{}' already exists", name);
      throw new WebApplicationException(Response.Status.CONFLICT);
    }
    return JsonConv.full(managedAcl.get()).toString();
  }

  @PUT
  @Path("/acl/{aclId}")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Update an ACL",
      description = "Update an ACL"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The ACL has successfully been updated"),
      @ApiResponse(responseCode = "404", description = "The ACL has not been found"),
      @ApiResponse(responseCode = "400", description = "Unable to parse the ACL"),
      @ApiResponse(responseCode = "500", description = "Error during updating the ACL")
  })
  public String updateAcl(
      @Parameter(description = "The ACL identifier", required = true)
      @PathParam("aclId") long aclId,
      @Parameter(description = "The ACL name", required = true)
      @FormParam("name") String name,
      @Parameter(description = "The access control list", required = true)
      @FormParam("acl") String accessControlList
  ) throws NotFoundException {
    final Organization org = getSecurityService().getOrganization();
    final AccessControlList acl = parseAcl(accessControlList);
    final ManagedAclImpl managedAcl = new ManagedAclImpl(aclId, name, org.getId(), acl);
    if (!aclService().updateAcl(managedAcl)) {
      logger.info("No ACL with id '{}' could be found under organization '{}'", aclId, org.getId());
      throw new NotFoundException();
    }
    return JsonConv.full(managedAcl).toString();
  }

  @DELETE
  @Path("/acl/{aclId}")
  @Operation(
      summary = "Delete an ACL",
      description = "Delete an ACL"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The ACL has successfully been deleted"),
      @ApiResponse(responseCode = "404", description = "The ACL has not been found"),
      @ApiResponse(
          responseCode = "409",
          description = "The ACL could not be deleted, there are still references on it"
      ),
      @ApiResponse(responseCode = "500", description = "Error during deleting the ACL")
  })
  public Response deleteAcl(
      @Parameter(description = "The ACL identifier", required = true)
      @PathParam("aclId") long aclId
  ) throws NotFoundException {
    try {
      if (!aclService().deleteAcl(aclId)) {
        return conflict();
      }
    } catch (AclServiceException e) {
      logger.warn("Error deleting manged acl with id '{}'", aclId, e);
      throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }
    return noContent();
  }

  @POST
  @Path("/apply/episode/{episodeId}")
  @Operation(
      summary = "Apply an ACL to an episode",
      description = "Immediate application of an ACL to an episode (Attention: This endpoint is deprecated and "
          + "will be removed in future versions!)",
      deprecated = true
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The ACL has been successfully applied"),
      @ApiResponse(responseCode = "404", description = "The ACL or the episode has not been found"),
      @ApiResponse(responseCode = "500", description = "Internal error")
  })
  public Response applyAclToEpisode(
      @Parameter(description = "The episode ID", required = true)
      @PathParam("episodeId") String episodeId,
      @Parameter(
          description = "The ID of the ACL to apply. If missing the episode ACL will be "
              + "deleted to fall back to the series ACL"
      )
      @FormParam("aclId") Long aclId
  ) {
    try {
      final Optional<AccessControlList> aclOpt;
      if (aclId == null) {
        aclOpt = Optional.empty();
      } else {
        Optional<ManagedAcl> macl = aclService().getAcl(aclId);
        if (macl.isEmpty()) {
          return notFound();
        }
        aclOpt = Optional.of(macl.get().getAcl());
      }
      Optional<MediaPackage> mediaPackage = getAssetManager().getMediaPackage(episodeId);
      // the episode service is the source of authority for the retrieval of media packages
      if (mediaPackage.isPresent()) {
        MediaPackage episodeSvcMp = mediaPackage.get();
        aclOpt.ifPresentOrElse(
            acl -> { // "some" branch
              try {
                MediaPackage mp = getAuthorizationService()
                    .setAcl(episodeSvcMp, AclScope.Episode, acl)
                    .getA();
                getAssetManager().takeSnapshot(mp);
              } catch (MediaPackageException e) {
                logger.error("Error getting ACL from media package", e);
              }
            },
            () -> { // "none" branch
              MediaPackage mp = getAuthorizationService()
                  .removeAcl(episodeSvcMp, AclScope.Episode);
              getAssetManager().takeSnapshot(mp);
            }
        );
        return ok();
      }
      // not found
      return notFound();
    } catch (Exception e) {
      logger.error("Error applying acl to episode {}", episodeId);
      return serverError();
    }
  }

  private static AccessControlList parseAcl(String acl) {
    try {
      return AccessControlParser.parseAcl(acl);
    } catch (Exception e) {
      logger.warn("Unable to parse ACL");
      throw new WebApplicationException(Response.Status.BAD_REQUEST);
    }
  }

  private AclService aclService() {
    return getAclServiceFactory().serviceFor(getSecurityService().getOrganization());
  }
}
