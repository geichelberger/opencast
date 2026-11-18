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

package org.opencastproject.adminui.endpoint;

import static java.lang.Math.max;
import static javax.servlet.http.HttpServletResponse.SC_CONFLICT;
import static javax.servlet.http.HttpServletResponse.SC_FORBIDDEN;
import static javax.servlet.http.HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
import static javax.servlet.http.HttpServletResponse.SC_NOT_FOUND;
import static org.opencastproject.index.service.util.JSONUtils.safeString;
import static org.opencastproject.index.service.util.RestUtils.okJsonList;

import org.opencastproject.index.service.api.IndexService;
import org.opencastproject.index.service.util.RestUtils;
import org.opencastproject.list.common.query.GroupsListQuery;
import org.opencastproject.opensearch.index.OpenSearchIndex;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.security.api.UnauthorizedException;
import org.opencastproject.security.api.User;
import org.opencastproject.security.api.UserDirectoryService;
import org.opencastproject.security.impl.jpa.JpaGroup;
import org.opencastproject.userdirectory.ConflictException;
import org.opencastproject.userdirectory.JpaGroupRoleProvider;
import org.opencastproject.util.NotFoundException;
import org.opencastproject.util.requests.SortCriterion;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

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
import javax.ws.rs.core.Response.Status;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

@Path("/admin-ng/groups")
@Tag(
    name = "Admin UI - Groups",
    description = "Provides operations for groups"
)
@Component(
    immediate = true,
    service = GroupsEndpoint.class,
    property = {
        "service.description=Admin UI - Groups Endpoint",
        "opencast.service.type=org.opencastproject.adminui.GroupsEndpoint",
        "opencast.service.path=/admin-ng/groups",
    }
)
@JaxrsResource
public class GroupsEndpoint {

  /** The logging facility */
  private static final Logger logger = LoggerFactory.getLogger(GroupsEndpoint.class);

  /** The admin UI search index */
  private OpenSearchIndex searchIndex;

  /** The security service */
  private SecurityService securityService;

  /** The user directory service */
  private UserDirectoryService userDirectoryService;

  /** The index service */
  private IndexService indexService;

  /** The group provider */
  private JpaGroupRoleProvider jpaGroupRoleProvider;

  /** OSGi callback for the security service. */
  @Reference
  public void setSecurityService(SecurityService securityService) {
    this.securityService = securityService;
  }

  /** OSGi callback for the index service. */
  @Reference
  public void setIndexService(IndexService indexService) {
    this.indexService = indexService;
  }

  /** OSGi callback for users services. */
  @Reference
  public void setUserDirectoryService(UserDirectoryService userDirectoryService) {
    this.userDirectoryService = userDirectoryService;
  }

  /** OSGi callback for the search index. */
  @Reference
  public void setSearchIndex(OpenSearchIndex searchIndex) {
    this.searchIndex = searchIndex;
  }

  /** OSGi callback for the group provider. */
  @Reference
  public void setGroupRoleProvider(JpaGroupRoleProvider jpaGroupRoleProvider) {
    this.jpaGroupRoleProvider = jpaGroupRoleProvider;
  }

  /** OSGi callback. */
  @Activate
  protected void activate(ComponentContext cc) {
    logger.info("Activate the Admin ui - Groups facade endpoint");
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("groups.json")
  @Operation(
      summary = "Get groups",
      description = "Returns a list of groups"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The groups.")
  })
  public Response getGroups(
      @Parameter(description = "Filter used for the query, formatted like: 'filter1:value1,filter2:value2'")
      @QueryParam("filter") String filter,
      @Parameter(
          description = "The sort order. May include any of the following: NAME, DESCRIPTION, ROLE. "
              + "Add '_DESC' to reverse the sort order (e.g. NAME_DESC)."
      )
      @QueryParam("sort") String sort,
      @Parameter(description = "The page number.", example = "0")
      @QueryParam("offset") Integer offset,
      @Parameter(description = "The maximum number of items to return per page.", example = "100")
      @QueryParam("limit") Integer limit
  ) throws IOException {
    Optional<Integer> optLimit = Optional.ofNullable(limit);
    Optional<Integer> optOffset = Optional.ofNullable(offset);

    Map<String, String> filters = RestUtils.parseFilter(filter);
    Optional<String> optNameFilter = Optional.ofNullable(filters.get(GroupsListQuery.FILTER_NAME_NAME));
    Optional<String> optRoleFilter = Optional.ofNullable(filters.get(GroupsListQuery.FILTER_ROLE_NAME));
    Optional<String> optTextFilter = Optional.ofNullable(filters.get(GroupsListQuery.FILTER_TEXT_NAME));

    ArrayList<SortCriterion> sortCriteria = RestUtils.parseSortQueryParameter(sort);

    List<JpaGroup> results = jpaGroupRoleProvider.getGroups(optLimit, optOffset, optNameFilter, optRoleFilter,
        optTextFilter, sortCriteria);

    // load users
    List<String> userNames = results.stream().flatMap(item -> item.getMembers().stream())
            .collect(Collectors.toList());
    final Map<String, User> users = new HashMap<>(userNames.size());
    userDirectoryService.loadUsers(userNames).forEachRemaining(user -> users.put(user.getUsername(), user));

    List<JsonObject> groupsJsonArray = new ArrayList<>();
    for (JpaGroup group : results) {
      JsonObject groupJson = new JsonObject();
      groupJson.addProperty("id", group.getGroupId());
      groupJson.addProperty("name", safeString(group.getName()));
      groupJson.addProperty("description", safeString(group.getDescription()));
      groupJson.addProperty("role", group.getRole());
      groupJson.add("users",
          membersToJSON(group.getMembers().stream().map(users::get).filter(Objects::nonNull).iterator()));

      groupsJsonArray.add(groupJson);
    }

    long dbTotal = jpaGroupRoleProvider.countTotalGroups(optNameFilter, optRoleFilter, optTextFilter);
    long resultsTotal = optOffset.orElse(0) + results.size();

    // groups could've been added or deleted in the meantime, so...
    long total;
    // don't show next page if current page isn't full
    if (!optLimit.isPresent() || results.size() < optLimit.get()) {
      total = resultsTotal;
      // don't show less than the current results
    } else {
      total = max(dbTotal, resultsTotal);
    }

    return okJsonList(groupsJsonArray, optOffset, optLimit, total);
  }

  @DELETE
  @Path("{id}")
  @Operation(
      summary = "Remove a group",
      description = "Remove a group"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Group deleted"),
      @ApiResponse(
          responseCode = "403",
          description = "Not enough permissions to delete the group with " + "admin role."
      ),
      @ApiResponse(responseCode = "404", description = "Group not found."),
      @ApiResponse(responseCode = "500", description = "An internal server error occured.")
  })
  public Response removeGroup(
      @Parameter(description = "The group identifier", required = true)
      @PathParam("id") String groupId
  ) throws NotFoundException {
    try {
      jpaGroupRoleProvider.removeGroup(groupId);
      return Response.noContent().build();
    } catch (NotFoundException e) {
      return Response.status(SC_NOT_FOUND).build();
    } catch (UnauthorizedException e) {
      return Response.status(SC_FORBIDDEN).build();
    } catch (Exception e) {
      logger.error("Unable to delete group {}", groupId, e);
      throw new WebApplicationException(e, SC_INTERNAL_SERVER_ERROR);
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
      @ApiResponse(
          responseCode = "403",
          description = "Not enough permissions to create a group with " + "admin role."
      ),
      @ApiResponse(responseCode = "409", description = "An group with this name already exists.")
  })
  public Response createGroup(
      @Parameter(description = "The group name", required = true)
      @FormParam("name") String name,
      @Parameter(description = "The group description")
      @FormParam("description") String description,
      @Parameter(description = "Comma seperated list of roles")
      @FormParam("roles") String roles,
      @Parameter(description = "Comma seperated list of members")
      @FormParam("users") String users
  ) {
    try {
      jpaGroupRoleProvider.createGroup(name, description, roles, users);
    } catch (IllegalArgumentException e) {
      logger.warn("Unable to create group with name {}: {}", name, e.getMessage());
      return Response.status(Status.BAD_REQUEST).build();
    } catch (UnauthorizedException e) {
      return Response.status(SC_FORBIDDEN).build();
    } catch (ConflictException e) {
      return Response.status(SC_CONFLICT).build();
    }
    return Response.status(Status.CREATED).build();
  }

  @PUT
  @Path("{id}")
  @Operation(
      summary = "Update a group",
      description = "Update a group"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Group updated"),
      @ApiResponse(
          responseCode = "403",
          description = "Not enough permissions to update the group with " + "admin role."
      ),
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
      @Parameter(description = "Comma seperated list of roles")
      @FormParam("roles") String roles,
      @Parameter(description = "Comma seperated list of members")
      @FormParam("users") String users
  ) throws NotFoundException {
    try {
      jpaGroupRoleProvider.updateGroup(groupId, name, description, roles, users);
    } catch (IllegalArgumentException e) {
      logger.warn("Unable to update group with id {}: {}", groupId, e.getMessage());
      return Response.status(Status.BAD_REQUEST).build();
    } catch (UnauthorizedException ex) {
      return Response.status(SC_FORBIDDEN).build();
    }
    return Response.ok().build();
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("{id}")
  @Operation(
      summary = "Get a group",
      description = "Get a single group"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Group found and returned as JSON"),
      @ApiResponse(responseCode = "404", description = "Group not found")
  })
  public Response getGroup(
      @Parameter(description = "The group identifier", required = true)
      @PathParam("id") String groupId
  ) throws NotFoundException {
    JpaGroup group = jpaGroupRoleProvider.getGroup(groupId);

    if (group == null) {
      throw new NotFoundException("Group " + groupId + " does not exist.");
    }

    // Convert roles
    JsonArray rolesJSON = new JsonArray();
    for (String role : group.getRoleNames()) {
      rolesJSON.add(role);
    }

    Iterator<User> users = userDirectoryService.loadUsers(group.getMembers());
    JsonObject jsonGroup = new JsonObject();
    jsonGroup.addProperty("id", group.getGroupId());
    jsonGroup.addProperty("name", safeString(group.getName()));
    jsonGroup.addProperty("description", safeString(group.getDescription()));
    jsonGroup.addProperty("role", safeString(group.getRole()));
    jsonGroup.add("roles", rolesJSON);
    jsonGroup.add("users", membersToJSON(users));

    return RestUtils.okJson(jsonGroup);
  }

  /**
   * Generate a JSON array based on the given set of members
   *
   * @param members
   *          the members source
   * @return a JSON array ({@link JsonArray}) with the given members
   */

  private JsonArray membersToJSON(Iterator<User> members) {
    JsonArray membersJSON = new JsonArray();

    while (members.hasNext()) {
      User user = members.next();
      String name = user.getUsername();

      if (StringUtils.isNotBlank(user.getName())) {
        name = user.getName();
      }

      JsonObject jsonUser = new JsonObject();
      jsonUser.addProperty("username", user.getUsername());
      jsonUser.addProperty("name", name);

      membersJSON.add(jsonUser);
    }

    return membersJSON;
  }
}
