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

package org.opencastproject.userdirectory.endpoint;

import static javax.servlet.http.HttpServletResponse.SC_BAD_REQUEST;
import static javax.servlet.http.HttpServletResponse.SC_CONFLICT;
import static javax.servlet.http.HttpServletResponse.SC_CREATED;
import static javax.servlet.http.HttpServletResponse.SC_FORBIDDEN;
import static javax.servlet.http.HttpServletResponse.SC_NOT_FOUND;

import org.opencastproject.security.api.JaxbGroupList;
import org.opencastproject.security.api.UnauthorizedException;
import org.opencastproject.userdirectory.ConflictException;
import org.opencastproject.userdirectory.JpaGroupRoleProvider;
import org.opencastproject.util.NotFoundException;

import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.DELETE;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * A REST EndPoint for JpaGroupRoleProvider.
 */
@Path("/groups")
@Tag(
    name = "Internal group manager",
    description = "This service offers the ability to manage the groups for internal accounts."
)
@Component(
    property = {
        "service.description=Group Role REST EndPoint",
        "opencast.service.type=org.opencastproject.userdirectory.endpoint.GroupRoleEndpoint",
        "opencast.service.jobproducer=false",
        "opencast.service.path=/groups"
    },
    immediate = false,
    service = { GroupRoleEndpoint.class }
)
@JaxrsResource
public class GroupRoleEndpoint {

  /** The logger */
  private static final Logger logger = LoggerFactory.getLogger(GroupRoleEndpoint.class);

  /** the jpaGroupRoleProvider Impl service */
  private JpaGroupRoleProvider jpaGroupRoleProvider;

  /**
   * @param jpaGroupRoleProvider
   *          the jpaGroupRoleProvider to set
   */
  @Reference
  public void setJpaGroupRoleProvider(JpaGroupRoleProvider jpaGroupRoleProvider) {
    this.jpaGroupRoleProvider = jpaGroupRoleProvider;
  }

  /**
   * Callback for activation of this component.
   */
  @Activate
  public void activate() {
    logger.info("Activating  {}", getClass().getName());
  }

  @GET
  @Produces({ MediaType.TEXT_XML, MediaType.APPLICATION_JSON })
  @Path("groups.{format:xml|json}")
  @Operation(
      summary = "List the groups",
      description = "Returns a list of groups"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The groups."),
      @ApiResponse(responseCode = "500", description = "The groups could not be retrieved.")
  })
  public Response getGroupsAsJsonOrXml(
      @Parameter(description = "The output format (json or xml) of the response body.", required = true)
      @PathParam("format") String format,
      @Parameter(description = "The maximum number of items to return per page.", example = "100")
      @QueryParam("limit") int limit,
      @Parameter(description = "The index of the first item to return.", example = "0")
      @QueryParam("offset") int offset
  ) {
    try {
      final String type = "json".equals(format) ? MediaType.APPLICATION_JSON : MediaType.APPLICATION_XML;
      JaxbGroupList list = jpaGroupRoleProvider.getGroups(limit, offset);
      return Response.ok().entity(list).type(type).build();
    } catch (Exception e) {
      logger.info("Unable to get groups", e);
      return Response.serverError().entity(buildUnexpectedErrorMessage(e)).build();
    }
  }

  @DELETE
  @Path("{id}")
  @Operation(
      summary = "Remove a group",
      description = "Remove a group"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "403", description = "Not enough permissions to remove a group with the admin role."),
      @ApiResponse(responseCode = "404", description = "Group not found."),
      @ApiResponse(responseCode = "500", description = "An internal server error occured."),
      @ApiResponse(responseCode = "204", description = "Group deleted.")
  })
  public Response removeGroup(
      @Parameter(description = "The group identifier", required = true)
      @PathParam("id") String groupId
  ) {
    try {
      jpaGroupRoleProvider.removeGroup(groupId);
      return Response.noContent().build();
    } catch (NotFoundException e) {
      return Response.status(SC_NOT_FOUND).build();
    } catch (UnauthorizedException e) {
      return Response.status(SC_FORBIDDEN).build();
    } catch (Exception e) {
      throw new WebApplicationException(e);
    }
  }

  @POST
  @Path("")
  @Operation(
      summary = "Create a group",
      description = "Add a group"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "201", description = "Group created"),
      @ApiResponse(responseCode = "400", description = "Name too long"),
      @ApiResponse(responseCode = "403", description = "Not enough permissions to create a group with the admin role."),
      @ApiResponse(responseCode = "409", description = "A group with this name already exists.")
  })
  public Response createGroup(
      @Parameter(description = "The group name", required = true)
      @FormParam("name") String name,
      @Parameter(description = "The group description")
      @FormParam("description") String description,
      @Parameter(description = "A comma separated string of additional group roles")
      @FormParam("roles") String roles,
      @Parameter(description = "A comma separated string of group members")
      @FormParam("users") String users
  ) {
    try {
      jpaGroupRoleProvider.createGroup(name, description, roles, users);
    } catch (IllegalArgumentException e) {
      logger.warn("Unable to create group {}: {}", name, e.getMessage());
      return Response.status(SC_BAD_REQUEST).build();
    } catch (UnauthorizedException e) {
      return Response.status(SC_FORBIDDEN).build();
    } catch (ConflictException e) {
      return Response.status(SC_CONFLICT).build();
    }
    return Response.status(SC_CREATED).build();
  }

  @PUT
  @Path("{id}")
  @Operation(
      summary = "Update a group",
      description = "Update a group"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Group updated"),
      @ApiResponse(responseCode = "403", description = "Not enough permissions to update a group with the admin role."),
      @ApiResponse(responseCode = "404", description = "Group not found"),
      @ApiResponse(responseCode = "400", description = "Name too long")
  })
  public Response updateGroup(
      @Parameter(description = "The group identifier", required = true)
      @PathParam("id") String groupId,
      @Parameter(description = "The group name", required = true)
      @FormParam("name") String name,
      @Parameter(description = "The group description")
      @FormParam("description") String description,
      @Parameter(description = "A comma separated string of additional group roles")
      @FormParam("roles") String roles,
      @Parameter(description = "A comma separated string of group members", required = true)
      @FormParam("users") String users
  ) throws NotFoundException {
    try {
      jpaGroupRoleProvider.updateGroup(groupId, name, description, roles, users);
    } catch (IllegalArgumentException e) {
      logger.warn("Unable to update group id {}: {}", groupId, e.getMessage());
      return Response.status(SC_BAD_REQUEST).build();
    } catch (UnauthorizedException ex) {
      return Response.status(SC_FORBIDDEN).build();
    }
    return Response.ok().build();
  }

  /**
   * Borrowed from FileUploadRestService.java
   *
   * Builds an error message in case of an unexpected error in an endpoint
   * method, includes the exception type and message if existing.
   *
   * TODO append stack trace
   *
   * @param e
   *          Exception that was thrown
   * @return error message
   */
  private String buildUnexpectedErrorMessage(Exception e) {
    StringBuilder sb = new StringBuilder();
    sb.append("Unexpected error (").append(e.getClass().getName()).append(")");
    String message = e.getMessage();
    if (StringUtils.isNotBlank(message)) {
      sb.append(": ").append(message);
    }
    return sb.toString();
  }
}
