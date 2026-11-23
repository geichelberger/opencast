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

package org.opencastproject.userdirectory;


import org.opencastproject.security.api.JaxbUser;
import org.opencastproject.security.api.JaxbUserList;
import org.opencastproject.security.api.User;
import org.opencastproject.security.api.UserDirectoryService;
import org.opencastproject.util.NotFoundException;

import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;

import java.io.IOException;
import java.util.Iterator;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * Provides a sorted set of known users
 */
@Path("/users")
@Tag(
    name = "User account manager",
    description = "Displays the users available in the current user's organization"
)
@Component(
    property = {
        "service.description=User listing REST endpoint",
        "opencast.service.type=org.opencastproject.userdirectory.users",
        "opencast.service.path=/users",
        "opencast.service.jobproducer=false"
    },
    immediate = true,
    service = { UserEndpoint.class }
)
@JaxrsResource
public class UserEndpoint {

  /** The role directory service */
  protected UserDirectoryService userDirectoryService = null;

  /**
   * Sets the user directory service
   *
   * @param userDirectoryService
   *          the userDirectoryService to set
   */
  @Reference
  public void setUserDirectoryService(UserDirectoryService userDirectoryService) {
    this.userDirectoryService = userDirectoryService;
  }

  @GET
  @Path("users.xml")
  @Produces(MediaType.APPLICATION_XML)
  @Operation(
      summary = "List the users as XML",
      description = "Returns a list of users"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The user accounts."),
      @ApiResponse(responseCode = "400", description = "The search query is shorter than 3 characters.")
  })
  public Response getUsersAsXml(
      @Parameter(description = "The search query, must be at lest 3 characters long.")
      @QueryParam("query") String queryString,
      @Parameter(description = "The maximum number of items to return per page.", example = "100")
      @QueryParam("limit") int limit,
      @Parameter(description = "The index of the first item to return.", example = "0")
      @QueryParam("offset") int offset
  ) throws IOException {
    if (limit < 1) {
      limit = 100;
    }

    String query = "%";
    if (StringUtils.isNotBlank(queryString)) {
      if (queryString.trim().length() < 3) {
        return Response.status(Status.BAD_REQUEST).build();
      }
      query = queryString;
    }

    JaxbUserList userList = new JaxbUserList();
    for (Iterator<User> i = userDirectoryService.findUsers(query, offset, limit); i.hasNext();) {
      userList.add(i.next());
    }
    return Response.ok(userList).build();
  }

  @GET
  @Path("users.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "List the users as JSON",
      description = "Returns a list of users"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The user accounts.")
  })
  public Response getUsersAsJson(
      @Parameter(description = "The search query, must be at lest 3 characters long.")
      @QueryParam("query") String queryString,
      @Parameter(description = "The maximum number of items to return per page.", example = "100")
      @QueryParam("limit") int limit,
      @Parameter(description = "The index of the first item to return.", example = "0")
      @QueryParam("offset") int offset
  ) throws IOException {
    return getUsersAsXml(queryString, limit, offset);
  }

  @GET
  @Path("{username}.xml")
  @Produces(MediaType.APPLICATION_XML)
  @Operation(
      summary = "Get a user as XML",
      description = "Returns a user"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The user account."),
      @ApiResponse(responseCode = "404", description = "User not found")
  })
  public JaxbUser getUserAsXml(
      @Parameter(description = "The username.", required = true)
      @PathParam("username") String username
  ) throws NotFoundException {
    User user = userDirectoryService.loadUser(username);
    if (user == null) {
      throw new NotFoundException();
    }
    return JaxbUser.fromUser(user);
  }

  @GET
  @Path("{username}.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get a user as JSON",
      description = "Returns a user"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The user account."),
      @ApiResponse(responseCode = "404", description = "User not found")
  })
  public JaxbUser getUserAsJson(
      @Parameter(description = "The username.", required = true)
      @PathParam("username") String username
  ) throws NotFoundException {
    return getUserAsXml(username);
  }

}
