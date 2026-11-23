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

import static org.apache.hc.core5.http.HttpStatus.SC_BAD_REQUEST;
import static org.apache.hc.core5.http.HttpStatus.SC_CONFLICT;
import static org.apache.hc.core5.http.HttpStatus.SC_FORBIDDEN;
import static org.apache.hc.core5.http.HttpStatus.SC_INTERNAL_SERVER_ERROR;
import static org.apache.hc.core5.http.HttpStatus.SC_NOT_FOUND;
import static org.apache.hc.core5.http.HttpStatus.SC_OK;
import static org.opencastproject.util.RestUtil.getEndpointUrl;
import static org.opencastproject.util.UrlSupport.uri;

import org.opencastproject.security.api.JaxbUser;
import org.opencastproject.security.api.JaxbUserList;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.security.api.UnauthorizedException;
import org.opencastproject.security.api.User;
import org.opencastproject.security.impl.jpa.JpaOrganization;
import org.opencastproject.security.impl.jpa.JpaRole;
import org.opencastproject.security.impl.jpa.JpaUser;
import org.opencastproject.userdirectory.JpaUserAndRoleProvider;
import org.opencastproject.util.NotFoundException;
import org.opencastproject.util.UrlSupport;
import org.opencastproject.util.data.Tuple;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;

import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import javax.persistence.RollbackException;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * Provides a sorted set of known users
 */
@Path("/user-utils")
@Tag(
    name = "User utils",
    description = "Provides operations for internal Opencast users"
)
@Component(
    property = {
        "service.description=User REST endpoint",
        "opencast.service.type=org.opencastproject.userdirectory.endpoint.UserEndpoint",
        "opencast.service.path=/user-utils",
        "opencast.service.jobproducer=false"
    },
    immediate = true,
    service = { UserEndpoint.class }
)
@JaxrsResource
public class UserEndpoint {

  /** The logger */
  private static final Logger logger = LoggerFactory.getLogger(UserEndpoint.class);

  private JpaUserAndRoleProvider jpaUserAndRoleProvider;

  private SecurityService securityService;

  private String endpointBaseUrl;

  private static final Gson gson = new Gson();

  private class UserData {
    private String username;
    private String password;
    private String name;
    private String email;
    private Set<String> roles;
  }

  private final Type userListType = new TypeToken<List<User>>() { }.getType();

  /** OSGi callback. */
  public void activate(ComponentContext cc) {
    logger.info("Start users endpoint");
    final Tuple<String, String> endpointUrl = getEndpointUrl(cc);
    endpointBaseUrl = UrlSupport.concat(endpointUrl.getA(), endpointUrl.getB());
  }

  /**
   * @param securityService
   *          the securityService to set
   */
  @Reference
  public void setSecurityService(SecurityService securityService) {
    this.securityService = securityService;
  }

  /**
   * @param jpaUserAndRoleProvider
   *          the persistenceProperties to set
   */
  @Reference
  public void setJpaUserAndRoleProvider(JpaUserAndRoleProvider jpaUserAndRoleProvider) {
    this.jpaUserAndRoleProvider = jpaUserAndRoleProvider;
  }

  @GET
  @Path("users.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "List the users",
      description = "Returns a list of users"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The user accounts.")
  })
  public JaxbUserList getUsersAsJson(
      @Parameter(description = "The maximum number of items to return per page.", example = "100")
      @QueryParam("limit") int limit,
      @Parameter(description = "The index of the first item to return.", example = "0")
      @QueryParam("offset") int offset
  ) throws IOException {

    // Set the maximum number of items to return to 100 if this limit parameter is not given
    if (limit < 1) {
      limit = 100;
    }

    JaxbUserList userList = new JaxbUserList();
    for (Iterator<User> i = jpaUserAndRoleProvider.findUsers("%", offset, limit); i.hasNext();) {
      userList.add(i.next());
    }
    return userList;
  }

  @GET
  @Path("{username}.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get a user",
      description = "Returns a user"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The user account."),
      @ApiResponse(responseCode = "404", description = "User not found")
  })
  public Response getUserAsJson(
      @Parameter(description = "The username.", required = true)
      @PathParam("username") String username
  ) throws NotFoundException {
    User user = jpaUserAndRoleProvider.loadUser(username);
    if (user == null) {
      logger.debug("Requested user not found: {}", username);
      return Response.status(SC_NOT_FOUND).build();
    }
    return Response.ok(JaxbUser.fromUser(user)).build();
  }

  @GET
  @Path("users/md5.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "List the users with insecure password hashing",
      description = "Returns a list of users which passwords are stored using MD5 hashes"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The user accounts.")
  })
  public JaxbUserList getUserWithInsecurePasswordHashingAsJson() {
    JaxbUserList userList = new JaxbUserList();
    for (User user: jpaUserAndRoleProvider.findInsecurePasswordHashes()) {
      userList.add(user);
    }
    return userList;
  }

  @POST
  @Path("/")
  @Operation(
      summary = "Create a user",
      description = "Create a new user"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "400", description = "Malformed request syntax."),
      @ApiResponse(responseCode = "201", description = "User has been created."),
      @ApiResponse(responseCode = "409", description = "An user with this username already exist."),
      @ApiResponse(responseCode = "403", description = "Not enough permissions to create a user with the admin role.")
  })
  public Response createUser(
      @Parameter(description = "The username.", required = true)
      @FormParam("username") String username,
      @Parameter(description = "The password.", required = true)
      @FormParam("password") String password,
      @Parameter(description = "The name.")
      @FormParam("name") String name,
      @Parameter(description = "The email.")
      @FormParam("email") String email,
      @Parameter(description = "The user roles as a json array, for example: [\"ROLE_USER\", \"ROLE_ADMIN\"]")
      @FormParam("roles") String roles
  ) {

    if (jpaUserAndRoleProvider.loadUser(username) != null) {
      return Response.status(SC_CONFLICT).build();
    }

    try {
      Set<JpaRole> rolesSet = parseRoles(roles);

      /* Add new user */
      logger.debug("Updating user {}", username);
      JpaOrganization organization = (JpaOrganization) securityService.getOrganization();
      JpaUser user = new JpaUser(username, password, organization, name, email, jpaUserAndRoleProvider.getName(), true,
              rolesSet);
      try {
        jpaUserAndRoleProvider.addUser(user);
        return Response.created(uri(endpointBaseUrl, user.getUsername() + ".json")).build();
      } catch (UnauthorizedException ex) {
        logger.debug("Create user failed", ex);
        return Response.status(Response.Status.FORBIDDEN).build();
      }

    } catch (IllegalArgumentException e) {
      logger.debug("Request with malformed ROLE data: {}", roles);
      return Response.status(SC_BAD_REQUEST).build();
    }
  }

  @POST
  @Path("/users.json")
  @Consumes(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Create multiple users",
      description = "Create a list of new users"
  )
  @RequestBody(
      description = "A JSON array of users. Each user has a `username` (required), a `password`, a `name`, "
          + "an `email` and `roles`, an array of role names.",
      required = true,
      content = @Content(
          mediaType = MediaType.APPLICATION_JSON,
          schema = @Schema(
              type = "array",
              example = "[{\"username\": \"jdoe\", \"password\": \"password\", \"name\": \"Jane Doe\", "
                  + "\"email\": \"jdoe@example.com\", \"roles\": [\"ROLE_USER\"]}]"
          )
      )
  )
  @ApiResponses({
      @ApiResponse(responseCode = "400", description = "Malformed request syntax."),
      @ApiResponse(responseCode = "409", description = "At least one user already existed."),
      @ApiResponse(responseCode = "201", description = "Users have been created.")
  })
  public Response createUsers(String body) throws UnauthorizedException {
    logger.debug("Provided user JSON: {}", body);
    try {
      for (var user: parseUserData(body)) {
        jpaUserAndRoleProvider.addUser(user);
        logger.info("Created user {}", user.getUsername());
      }
    } catch (RollbackException e) {
      logger.debug("Error storing user in database", e);
      return Response.status(Response.Status.CONFLICT).build();
    } catch (IllegalArgumentException e) {
      logger.debug("Error parsing the provided JSON body", e);
      return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
    }
    return Response.status(Response.Status.CREATED).build();
  }

  @PUT
  @Path("{username}.json")
  @Operation(
      summary = "Update a user",
      description = "Updates a user. If no user with the given username exists, the user is created instead."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "400", description = "Malformed request syntax."),
      @ApiResponse(responseCode = "403", description = "Not enough permissions to update a user with the admin role."),
      @ApiResponse(responseCode = "200", description = "User has been updated."),
      @ApiResponse(responseCode = "201", description = "The user did not exist and has been created."),
      @ApiResponse(responseCode = "404", description = "The user does not exist anymore.")
  })
  public Response setUser(
      @Parameter(description = "The username", required = true)
      @PathParam("username") String username,
      @Parameter(description = "The password.", required = true)
      @FormParam("password") String password,
      @Parameter(description = "The name.")
      @FormParam("name") String name,
      @Parameter(description = "The email.")
      @FormParam("email") String email,
      @Parameter(description = "The user roles as a json array, for example: [\"ROLE_USER\", \"ROLE_ADMIN\"]")
      @FormParam("roles") String roles
  ) {

    try {
      User user = jpaUserAndRoleProvider.loadUser(username);
      if (user == null) {
        return createUser(username, password, name, email, roles);
      }

      Set<JpaRole> rolesSet = parseRoles(roles);

      logger.debug("Updating user {}", username);
      JpaOrganization organization = (JpaOrganization) securityService.getOrganization();
      jpaUserAndRoleProvider.updateUser(new JpaUser(username, password, organization, name, email,
                jpaUserAndRoleProvider.getName(), true, rolesSet));
      return Response.status(SC_OK).build();
    } catch (NotFoundException e) {
      logger.debug("User {} not found.", username);
      return Response.status(SC_NOT_FOUND).build();
    } catch (UnauthorizedException e) {
      logger.debug("Update user failed", e);
      return Response.status(Response.Status.FORBIDDEN).build();
    } catch (IllegalArgumentException e) {
      logger.debug("Request with malformed ROLE data: {}", roles);
      return Response.status(SC_BAD_REQUEST).build();
    }
  }

  @DELETE
  @Path("{username}.json")
  @Operation(
      summary = "Delete a user",
      description = "Delete a user"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "User has been deleted."),
      @ApiResponse(responseCode = "403", description = "Not enough permissions to delete a user with the admin role."),
      @ApiResponse(responseCode = "404", description = "User not found."),
      @ApiResponse(responseCode = "500", description = "The user could not be deleted.")
  })
  public Response deleteUser(
      @Parameter(description = "The username", required = true)
      @PathParam("username") String username
  ) {
    try {
      jpaUserAndRoleProvider.deleteUser(username, securityService.getOrganization().getId());
    } catch (NotFoundException e) {
      logger.debug("User {} not found.", username);
      return Response.status(SC_NOT_FOUND).build();
    } catch (UnauthorizedException e) {
      logger.debug("Error during deletion of user {}", username, e);
      return Response.status(SC_FORBIDDEN).build();
    } catch (Exception e) {
      logger.error("Error during deletion of user {}", username, e);
      return Response.status(SC_INTERNAL_SERVER_ERROR).build();
    }

    logger.debug("User {} removed.", username);
    return Response.status(SC_OK).build();
  }

  /**
   * Parse JSON roles array.
   *
   * @param roles
   *          String representation of JSON array containing roles
   */
  private Set<JpaRole> parseRoles(String roles) throws IllegalArgumentException {
    /* Try parsing JSON. Return Bad Request if malformed. */
    final String[] rolesArray;
    try {
      rolesArray = gson.fromJson(StringUtils.isEmpty(roles) ? "[]" : roles, String[].class);
    } catch (JsonSyntaxException e) {
      throw new IllegalArgumentException("Error parsing JSON array", e);
    }

    Set<JpaRole> rolesSet = new HashSet<>();
    /* Add given roles */
    for (var role : rolesArray) {
      rolesSet.add(new JpaRole(role, (JpaOrganization) securityService.getOrganization()));
    }

    return rolesSet;
  }

  private List<JpaUser> parseUserData(String userJson) {
    final UserData[] userArray;
    try {
      userArray = gson.fromJson(userJson, UserData[].class);
    } catch (JsonSyntaxException e) {
      throw new IllegalArgumentException("Error parsing JSON array", e);
    }

    if (Objects.isNull(userArray)) {
      throw new IllegalArgumentException("The JSON may not be empty or `null`");
    }

    var users = new ArrayList<JpaUser>(userArray.length);
    var organization = (JpaOrganization) securityService.getOrganization();
    var provider = jpaUserAndRoleProvider.getName();
    for (var u: userArray) {
      if (Objects.isNull(u.username)) {
        throw new IllegalArgumentException("Field `username` may not be `null`");
      }
      // parse roles
      Set<JpaRole> roles = Objects.isNull(u.roles)
          ? Collections.emptySet()
          : u.roles.stream().map(r -> new JpaRole(r, organization)).collect(Collectors.toSet());
      users.add(new JpaUser(u.username, u.password, organization, u.name, u.email, provider, true, roles));
    }
    return users;
  }

}
