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
package org.opencastproject.external.endpoint;

import static javax.servlet.http.HttpServletResponse.SC_BAD_REQUEST;
import static javax.servlet.http.HttpServletResponse.SC_CONFLICT;
import static javax.servlet.http.HttpServletResponse.SC_CREATED;
import static javax.servlet.http.HttpServletResponse.SC_FORBIDDEN;
import static javax.servlet.http.HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
import static javax.servlet.http.HttpServletResponse.SC_NOT_FOUND;
import static org.apache.commons.lang3.exception.ExceptionUtils.getMessage;
import static org.opencastproject.external.common.ApiVersion.VERSION_1_6_0;
import static org.opencastproject.index.service.util.JSONUtils.safeString;

import org.opencastproject.external.common.ApiMediaType;
import org.opencastproject.external.common.ApiResponseBuilder;
import org.opencastproject.external.common.ApiVersion;
import org.opencastproject.index.service.util.RestUtils;
import org.opencastproject.list.common.query.GroupsListQuery;
import org.opencastproject.opensearch.index.OpenSearchIndex;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.security.api.UnauthorizedException;
import org.opencastproject.security.impl.jpa.JpaGroup;
import org.opencastproject.userdirectory.ConflictException;
import org.opencastproject.userdirectory.JpaGroupRoleProvider;
import org.opencastproject.util.NotFoundException;
import org.opencastproject.util.requests.SortCriterion;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import org.apache.commons.collections4.ComparatorUtils;
import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.ws.rs.DELETE;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

@Path("/api/groups")
@Produces({ ApiMediaType.JSON, ApiMediaType.VERSION_1_0_0, ApiMediaType.VERSION_1_1_0, ApiMediaType.VERSION_1_2_0,
            ApiMediaType.VERSION_1_3_0, ApiMediaType.VERSION_1_4_0, ApiMediaType.VERSION_1_5_0,
            ApiMediaType.VERSION_1_6_0, ApiMediaType.VERSION_1_7_0, ApiMediaType.VERSION_1_8_0,
            ApiMediaType.VERSION_1_9_0, ApiMediaType.VERSION_1_10_0, ApiMediaType.VERSION_1_11_0,
            ApiMediaType.VERSION_1_12_0 })
@Tag(name = "External API")
@Tag(
    name = "External API - Groups",
    description = "Provides resources and operations related to the groups"
)
@Component(
    immediate = true,
    service = GroupsEndpoint.class,
    property = {
        "service.description=External API - Groups Endpoint",
        "opencast.service.type=org.opencastproject.external.groups",
        "opencast.service.path=/api/groups"
    }
)
@JaxrsResource
public class GroupsEndpoint {

  /** The logging facility */
  private static final Logger logger = LoggerFactory.getLogger(GroupsEndpoint.class);

  /* OSGi service references */
  private OpenSearchIndex opensearchIndex;
  private JpaGroupRoleProvider jpaGroupRoleProvider;
  private SecurityService securityService;

  /** OSGi DI */
  @Reference
  void setOpenSearchIndex(OpenSearchIndex opensearchIndex) {
    this.opensearchIndex = opensearchIndex;
  }

  /** OSGi DI. */
  @Reference
  public void setSecurityService(SecurityService securityService) {
    this.securityService = securityService;
  }

  /** OSGi DI */
  @Reference
  public void setGroupRoleProvider(JpaGroupRoleProvider jpaGroupRoleProvider) {
    this.jpaGroupRoleProvider = jpaGroupRoleProvider;
  }

  /** OSGi activation method */
  @Activate
  void activate() {
    logger.info("Activating External API - Groups Endpoint");
  }

  @GET
  @Path("")
  @Operation(
      summary = "Get groups",
      description = "Returns a list of groups."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "A (potentially empty) list of groups.")
  })
  public Response getGroups(
      @HeaderParam("Accept") String acceptHeader,
      @Parameter(
          description = "A comma seperated list of filters to "
              + "limit the results with. A filter is the filter's name followed by a colon \":\" and then the value "
              + "to "
              + "filter with so it is the form [Filter Name]:[Value to Filter With]."
      )
      @QueryParam("filter") String filter,
      @Parameter(
          description = "Sort the results based upon a list of comma seperated sorting "
              + "criteria. In the comma seperated list each type of sorting is specified as a pair such as: "
              + "<Sort Name>:ASC or <Sort Name>:DESC. Adding the suffix ASC or DESC sets the order as ascending or "
              + "descending order and is mandatory."
      )
      @QueryParam("sort") String sort,
      @Parameter(description = "The index of the first result to return.")
      @QueryParam("offset") Integer offset,
      @Parameter(description = "The maximum number of results to return for a single request.")
      @QueryParam("limit") Integer limit
  ) {
    final ApiVersion requestedVersion = ApiMediaType.parse(acceptHeader).getVersion();
    Optional<Integer> optLimit = Optional.ofNullable(limit);
    Optional<Integer> optOffset = Optional.ofNullable(offset);

    if (optLimit.isPresent() && limit <= 0) {
      optLimit = Optional.empty();
    }
    if (optOffset.isPresent() && offset < 0) {
      optOffset = Optional.empty();
    }

    // The API currently does not offer full text search for groups
    Map<String, String> filters = new HashMap<>();
    if (StringUtils.isNotBlank(filter)) {
      for (String f : filter.split(",")) {
        String[] filterTuple = f.split(":");
        if (filterTuple.length < 2) {
          logger.debug("No value for filter '{}' in filters list: {}", filterTuple[0], filter);
          continue;
        }
        // use substring because dates also contain : so there might be more than two parts
        filters.put(filterTuple[0].trim(), f.substring(filterTuple[0].length() + 1).trim());
      }
    }
    Optional<String> optNameFilter = Optional.ofNullable(filters.get(GroupsListQuery.FILTER_NAME_NAME));

    ArrayList<SortCriterion> sortCriteria = RestUtils.parseSortQueryParameter(sort);

    // sorting by members & roles is not supported by the database, so we do this afterwards
    Set<SortCriterion> deprecatedSortCriteria = new HashSet<>();
    if (requestedVersion.isSmallerThan(VERSION_1_6_0)) {
      deprecatedSortCriteria = sortCriteria.stream().filter(
              sortCriterion -> sortCriterion.getFieldName().equals("members")
                      || sortCriterion.getFieldName().equals("roles")).collect(Collectors.toSet());
      sortCriteria.removeAll(deprecatedSortCriteria);
    }

    List<JpaGroup> results = jpaGroupRoleProvider.getGroups(optLimit, optOffset, optNameFilter,
        Optional.empty(), Optional.empty(), sortCriteria);

    // sorting by members & roles is only available for api versions < 1.6.0
    if (requestedVersion.isSmallerThan(VERSION_1_6_0)) {
      List<Comparator<JpaGroup>> comparators = new ArrayList<>();
      for (SortCriterion sortCriterion : deprecatedSortCriteria) {
        Comparator<JpaGroup> comparator;
        switch (sortCriterion.getFieldName()) {
          case "members":
            comparator = new GroupComparator() {
              @Override
              public Set<String> getGroupAttribute(JpaGroup jpaGroup) {
                return jpaGroup.getMembers();
              }
            };
            break;
          case "roles":
            comparator = new GroupComparator() {
              @Override
              public Set<String> getGroupAttribute(JpaGroup jpaGroup) {
                return jpaGroup.getRoleNames();
              }
            };
            break;
          default:
            continue;
        }

        if (sortCriterion.getOrder() == SortCriterion.Order.Descending) {
          comparator = comparator.reversed();
        }
        comparators.add(comparator);
      }
      if (!comparators.isEmpty()) {
        Collections.sort(results, ComparatorUtils.chainedComparator(comparators));
      }
    }

    List<JsonObject> groupsJson = new ArrayList<>();
    for (JpaGroup group : results) {
      JsonObject groupJson = new JsonObject();

      groupJson.addProperty("identifier", group.getGroupId());
      groupJson.addProperty("organization", group.getOrganization().getId());
      groupJson.addProperty("role", group.getRole());
      groupJson.addProperty("name", safeString(group.getName()));
      groupJson.addProperty("description", safeString(group.getDescription()));
      groupJson.addProperty("roles", group.getRoleNames() != null ? String.join(",", group.getRoleNames()) : "");
      groupJson.addProperty("members", group.getMembers() != null ? String.join(",", group.getMembers()) : "");

      groupsJson.add(groupJson);
    }
    JsonArray responseArray = new JsonArray();
    groupsJson.forEach(responseArray::add);

    return ApiResponseBuilder.Json.ok(acceptHeader, responseArray);
  }

  /**
   * Compare groups by set attributes like members or roles.
   */
  private abstract class GroupComparator implements Comparator<JpaGroup> {

    public abstract Set<String> getGroupAttribute(JpaGroup jpaGroup);

    @Override
    public int compare(JpaGroup group1, JpaGroup group2) {
      List<String> members1 = new ArrayList<>(getGroupAttribute(group1));
      List<String> members2 = new ArrayList<>(getGroupAttribute(group2));

      for (int i = 0; i < members1.size() && i < members2.size(); i++) {
        String member1 = members1.get(i);
        String member2 = members2.get(i);
        int result = member1.compareTo(member2);
        if (result != 0) {
          return result;
        }
      }
      return (members1.size() - members2.size());
    }
  }

  @GET
  @Path("{groupId}")
  @Operation(
      summary = "Get a group",
      description = "Returns a single group."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The group is returned."),
      @ApiResponse(responseCode = "404", description = "The specified group does not exist.")
  })
  public Response getGroup(
      @HeaderParam("Accept") String acceptHeader,
      @Parameter(description = "The group id", required = true)
      @PathParam("groupId") String id
  ) {
    JpaGroup group = jpaGroupRoleProvider.getGroup(id);

    if (group == null) {
      return ApiResponseBuilder.notFound("Cannot find a group with id '%s'.", id);
    }

    JsonObject json = new JsonObject();
    json.addProperty("identifier", group.getGroupId());
    json.addProperty("organization", group.getOrganization().getId());
    json.addProperty("role", group.getRole());
    json.addProperty("name", safeString(group.getName()));
    json.addProperty("description", safeString(group.getDescription()));
    json.addProperty("roles", safeString(group.getRoleNames()));
    json.addProperty("members", safeString(group.getMembers()));

    return ApiResponseBuilder.Json.ok(acceptHeader, json);
  }

  @DELETE
  @Path("{groupId}")
  @Operation(
      summary = "Delete a group",
      description = "Deletes a group."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "The group has been deleted."),
      @ApiResponse(responseCode = "404", description = "The specified group does not exist.")
  })
  public Response deleteGroup(
      @HeaderParam("Accept") String acceptHeader,
      @Parameter(description = "The group id", required = true)
      @PathParam("groupId") String id
  ) throws NotFoundException {
    try {
      jpaGroupRoleProvider.removeGroup(id);
      return Response.noContent().build();
    } catch (NotFoundException e) {
      return Response.status(SC_NOT_FOUND).build();
    } catch (UnauthorizedException e) {
      return Response.status(SC_FORBIDDEN).build();
    } catch (Exception e) {
      logger.error("Unable to delete group {}", id, e);
      throw new WebApplicationException(e, SC_INTERNAL_SERVER_ERROR);
    }
  }

  @PUT
  @Path("{groupId}")
  @Operation(
      summary = "Update a group",
      description = "Updates a group."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "201", description = "The group has been updated."),
      @ApiResponse(responseCode = "400", description = "The specified group does not exist.")
  })
  public Response updateGroup(
      @HeaderParam("Accept") String acceptHeader,
      @Parameter(description = "The group id", required = true)
      @PathParam("groupId") String id,
      @Parameter(description = "Group Name")
      @FormParam("name") String name,
      @Parameter(description = "Group Description")
      @FormParam("description") String description,
      @Parameter(description = "Comma-separated list of roles")
      @FormParam("roles") String roles,
      @Parameter(description = "Comma-separated list of members")
      @FormParam("members") String members
  ) throws Exception {
    try {
      jpaGroupRoleProvider.updateGroup(id, name, description, roles, members);
    } catch (IllegalArgumentException e) {
      logger.warn("Unable to update group id {}: {}", id, e.getMessage());
      return Response.status(SC_BAD_REQUEST).build();
    } catch (UnauthorizedException ex) {
      return Response.status(SC_FORBIDDEN).build();
    }
    return Response.ok().build();
  }

  @POST
  @Path("")
  @Operation(
      summary = "Create a group",
      description = "Creates a group."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "201", description = "A new group is created."),
      @ApiResponse(responseCode = "400", description = "The request is invalid or inconsistent.")
  })
  public Response createGroup(
      @HeaderParam("Accept") String acceptHeader,
      @Parameter(description = "Group Name", required = true)
      @FormParam("name") String name,
      @Parameter(description = "Group Description")
      @FormParam("description") String description,
      @Parameter(description = "Comma-separated list of roles")
      @FormParam("roles") String roles,
      @Parameter(description = "Comma-separated list of members")
      @FormParam("members") String members
  ) {
    try {
      jpaGroupRoleProvider.createGroup(name, description, roles, members);
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

  @POST
  @Path("{groupId}/members")
  @Operation(
      summary = "Add a member to a group",
      description = "Adds a member to a group."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The member was already member of the group."),
      @ApiResponse(responseCode = "204", description = "The member has been added."),
      @ApiResponse(responseCode = "404", description = "The specified group does not exist.")
  })
  public Response addGroupMember(
      @HeaderParam("Accept") String acceptHeader,
      @Parameter(description = "The group id", required = true)
      @PathParam("groupId") String id,
      @Parameter(description = "Member Name", required = true)
      @FormParam("member") String member
  ) {
    try {
      if (jpaGroupRoleProvider.addMemberToGroup(id, member)) {
        return Response.ok().build();
      } else {
        return ApiResponseBuilder.Json.ok(acceptHeader, "Member is already member of group.");
      }
    } catch (IllegalArgumentException e) {
      logger.warn("Unable to add member to group id {}.", id, e);
      return Response.status(SC_BAD_REQUEST).build();
    } catch (UnauthorizedException ex) {
      return Response.status(SC_FORBIDDEN).build();
    } catch (NotFoundException e) {
      return ApiResponseBuilder.notFound("Cannot find group with id '%s'.", id);
    } catch (Exception e) {
      logger.warn("Could not update the group with id {}.",id, e);
      return ApiResponseBuilder.serverError("Could not update group with id '%s', reason: '%s'",id,getMessage(e));
    }
  }

  @DELETE
  @Path("{groupId}/members/{memberId}")
  @Operation(
      summary = "Remove a member from a group",
      description = "Removes a member from a group"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "The member has been removed."),
      @ApiResponse(responseCode = "404", description = "The specified group or member does not exist.")
  })
  public Response removeGroupMember(
      @HeaderParam("Accept") String acceptHeader,
      @Parameter(description = "The group id", required = true)
      @PathParam("groupId") String id,
      @Parameter(description = "The member id", required = true)
      @PathParam("memberId") String memberId
  ) {
    try {
      if (jpaGroupRoleProvider.removeMemberFromGroup(id, memberId)) {
        return Response.ok().build();
      } else {
        return ApiResponseBuilder.Json.ok(acceptHeader, "Member is already not member of group.");
      }
    } catch (IllegalArgumentException e) {
      logger.warn("Unable to remove member from group id {}.", id, e);
      return Response.status(SC_BAD_REQUEST).build();
    } catch (UnauthorizedException ex) {
      return Response.status(SC_FORBIDDEN).build();
    } catch (NotFoundException e) {
      return ApiResponseBuilder.notFound("Cannot find group with id '%s'.", id);
    } catch (Exception e) {
      logger.warn("Could not update the group with id {}.", id, e);
      return ApiResponseBuilder.serverError("Could not update group with id '%s', reason: '%s'", id, getMessage(e));
    }
  }
}
