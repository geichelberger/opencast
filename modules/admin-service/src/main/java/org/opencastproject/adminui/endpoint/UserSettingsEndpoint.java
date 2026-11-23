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

import static org.apache.hc.core5.http.HttpStatus.SC_OK;
import static org.opencastproject.util.RestUtil.getEndpointUrl;

import org.opencastproject.adminui.usersettings.UserSetting;
import org.opencastproject.adminui.usersettings.UserSettings;
import org.opencastproject.adminui.usersettings.UserSettingsService;
import org.opencastproject.adminui.usersettings.persistence.UserSettingsServiceException;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.util.NotFoundException;
import org.opencastproject.util.UrlSupport;
import org.opencastproject.util.data.Tuple;

import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

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
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

@Path("/admin-ng/user-settings")
@Tag(
    name = "Admin UI - User Settings",
    description = "Provides operations for user settings"
)
@Component(
    immediate = true,
    service = UserSettingsEndpoint.class,
    property = {
        "service.description=Admin UI - Users Settings facade Endpoint",
        "opencast.service.type=org.opencastproject.adminui.endpoint.UserSettingsEndpoint",
        "opencast.service.path=/admin-ng/user-settings"
    }
)
@JaxrsResource
public class UserSettingsEndpoint {

  /** The logging facility */
  private static final Logger logger = LoggerFactory.getLogger(ServerEndpoint.class);

  /** Base url of this endpoint */
  private String endpointBaseUrl;

  private UserSettingsService userSettingsService;

  private SecurityService securityService;

  /**
   * OSGi callback to set the service to retrieve user settings from.
   */
  @Reference
  public void setUserSettingsService(UserSettingsService userSettingsService) {
    this.userSettingsService = userSettingsService;
  }

  /**
   * OSGi callback to set the security service
   */
  @Reference
  public void setSecurityService(SecurityService securityService) {
    this.securityService = securityService;
  }

  /** OSGi callback. */
  @Activate
  protected void activate(ComponentContext cc) {
    logger.info("Activate the Admin ui - Users facade endpoint");
    final Tuple<String, String> endpointUrl = getEndpointUrl(cc);
    endpointBaseUrl = UrlSupport.concat(endpointUrl.getA(), endpointUrl.getB());
  }

  @GET
  @Path("/settings.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the settings of the current user",
      description = "Returns a list of the user settings for the current user"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The user settings."),
      @ApiResponse(responseCode = "500", description = "The user settings could not be retrieved.")
  })
  public Response getUserSettings(
      @Parameter(description = "The maximum number of items to return per page.", example = "100")
      @QueryParam("limit") int limit,
      @Parameter(description = "The index of the first item to return.", example = "0")
      @QueryParam("offset") int offset
  ) throws IOException {
    if (limit < 1) {
      limit = 100;
    }

    UserSettings userSettings;
    try {
      userSettings = userSettingsService.findUserSettings(limit, offset);
    } catch (UserSettingsServiceException e) {
      logger.error("Unable to get user settings:", e);
      return (Response.serverError().build());
    }

    return Response.ok(userSettings.toJson().toString()).build();
  }

  @POST
  @Path("/setting")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Create a user setting",
      description = "Create a new user setting"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "User setting has been created."),
      @ApiResponse(responseCode = "500", description = "The user setting could not be created.")
  })
  public Response createUserSetting(
      @Parameter(description = "The key used to represent this setting.", required = true)
      @FormParam("key") String key,
      @Parameter(description = "The value representing this setting.", required = true)
      @FormParam("value") String value
  ) throws NotFoundException {
    String orgId = securityService.getOrganization().getId();
    String username = securityService.getUser().getUsername();
    try {
      UserSetting newUserSetting = userSettingsService.addUserSetting(key, value);
      return Response.ok(newUserSetting.toJson().toString(), MediaType.APPLICATION_JSON).build();
    } catch (UserSettingsServiceException e) {
      logger.error("Could not add user setting username '{}' org: '{}' key: '{}' value: '{}'", username, orgId,
          key, value);
      return Response.serverError().build();
    }
  }

  @PUT
  @Path("/setting/{settingId}")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Update a user setting",
      description = "Update a user setting"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "User setting has been created."),
      @ApiResponse(responseCode = "500", description = "The user setting could not be updated.")
  })
  public Response updateUserSetting(
      @Parameter(description = "The setting's id", required = true)
      @PathParam("settingId") final int id,
      @Parameter(description = "The key used to represent this setting.", required = true)
      @FormParam("key") String key,
      @Parameter(description = "The value representing this setting.", required = true)
      @FormParam("value") String value
  ) throws NotFoundException {
    try {
      UserSetting updatedUserSetting = userSettingsService.updateUserSetting(id, key, value);
      return Response.ok(updatedUserSetting.toJson().toString(), MediaType.APPLICATION_JSON).build();
    } catch (UserSettingsServiceException e) {
      logger.error("Unable to update user setting", e);
      return Response.serverError().build();
    }
  }

  @DELETE
  @Path("/setting/{settingId}")
  @Operation(
      summary = "Delete a user setting",
      description = "Delete a user setting"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "User setting has been deleted."),
      @ApiResponse(responseCode = "404", description = "User setting not found."),
      @ApiResponse(responseCode = "500", description = "The user setting could not be deleted.")
  })
  public Response deleteUserSetting(
      @Parameter(description = "The id of the user setting.", required = true)
      @PathParam("settingId") long id
  ) throws NotFoundException {
    try {
      userSettingsService.deleteUserSetting(id);
    } catch (UserSettingsServiceException e) {
      logger.error("Unable to remove user setting id: '{}'", id, e);
      return Response.serverError().build();
    }
    logger.debug("User setting with id {} removed.", id);
    return Response.status(SC_OK).build();
  }
}
