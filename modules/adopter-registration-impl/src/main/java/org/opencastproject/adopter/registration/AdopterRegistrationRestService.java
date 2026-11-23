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

package org.opencastproject.adopter.registration;

import static org.opencastproject.util.RestUtil.R.ok;
import static org.opencastproject.util.RestUtil.R.serverError;

import org.opencastproject.adopter.registration.dto.Adopter;

import com.google.gson.Gson;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Calendar;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.DELETE;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * The REST endpoint for the adopter statistics service.
 */
@Path("/admin-ng/adopter")
@Tag(
    name = "Adopter Statistics Registration Service Endpoint",
    description = "Rest Endpoint for the registration form."
)
@Component(
    immediate = true,
    service = AdopterRegistrationRestService.class,
    property = {
        "service.description=Adopter Statistics REST Endpoint",
        "opencast.service.type=org.opencastproject.adopter.registration.AdopterRegistrationRestService",
        "opencast.service.path=/admin-ng/adopter",
        "opencast.service.jobproducer=false"
    }
)
@JaxrsResource
public class AdopterRegistrationRestService {

  /** The logger */
  private static final Logger logger = LoggerFactory.getLogger(AdopterRegistrationRestService.class);

  /** The JSON parser */
  private static final Gson gson = new Gson();

  /** The service that provides methods for the registration */
  protected AdopterRegistrationServiceImpl registrationService;

  /** OSGi setter for the registration service */
  @Reference
  public void setRegistrationService(AdopterRegistrationServiceImpl registrationService) {
    this.registrationService = registrationService;
  }

  @GET
  @Path("registration")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the adopter registration data",
      description = "GETs the adopter registration data."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Retrieved registration data."),
      @ApiResponse(responseCode = "404", description = "No registration data found."),
      @ApiResponse(responseCode = "500", description = "Error while retrieving adopter registration data.")
  })
  public Response getRegistrationForm() {
    logger.debug("Retrieving adopter registration data.");
    Adopter a = registrationService.get();
    if (null != a) {
      return Response.ok(gson.toJson(a)).build();
    } else {
      return Response.status(HttpServletResponse.SC_NOT_FOUND).build();
    }
  }

  @GET
  @Path("statistics")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the adopter registration statistics",
      description = "GETs the adopter registration statistics data."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Retrieved statistic data."),
      @ApiResponse(responseCode = "500", description = "Error while retrieving adopter statistic data.")
  })
  public Response getAdopterStatistics() {
    logger.debug("Retrieving adopter registration statistics data.");
    try {
      return Response.ok(registrationService.getStatsDataAsString()).build();
    } catch (Exception e) {
      return Response.serverError().build();
    }
  }

  @POST
  @Path("registration")
  @Operation(
      summary = "Save the adopter registration data",
      description = "Saves the adopter registration data."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Adopter registration data saved."),
      @ApiResponse(responseCode = "500", description = "Couldn't save adopter registration data.")
  })
  public Response register(
      @Parameter(description = "The Name of the organisation.")
      @FormParam("organisationName") String organisationName,
      @Parameter(description = "The Name of the department.")
      @FormParam("departmentName") String departmentName,
      @Parameter(description = "The First name.")
      @FormParam("firstName") String firstName,
      @Parameter(description = "The Last name.")
      @FormParam("lastName") String lastName,
      @Parameter(description = "The e-mail address.")
      @FormParam("email") String email,
      @Parameter(description = "The country.")
      @FormParam("country") String country,
      @Parameter(description = "The postal code.")
      @FormParam("postalCode") String postalCode,
      @Parameter(description = "The city.")
      @FormParam("city") String city,
      @Parameter(description = "The street.")
      @FormParam("street") String street,
      @Parameter(description = "The street number.")
      @FormParam("streetNo") String streetNo,
      @Parameter(description = "Does the adopter allows to be contacted.")
      @FormParam("contactMe") boolean contactMe,
      @Parameter(description = "Does the adopter agreed to the policy.")
      @FormParam("agreedToPolicy") boolean agreedToPolicy,
      @Parameter(description = "Which type of system is this.")
      @FormParam("systemType") String systemType,
      @Parameter(description = "Does the adopter allow the gathering of error reports.")
      @FormParam("allowsErrorReports") boolean allowsErrorReports,
      @Parameter(description = "Does the adopter allow the gathering of statistic data.")
      @FormParam("allowsStatistics") boolean allowsStatistics,
      @Parameter(description = "Is the adopter already registered.")
      @FormParam("registered") boolean registered
  ) {
    logger.debug("Saving adopter registration data.");

    Adopter adopter = new Adopter(organisationName, departmentName, firstName, lastName, email, country, postalCode,
        city, street, streetNo, contactMe, systemType, allowsStatistics, allowsErrorReports, agreedToPolicy, registered
    );
    try {
      registrationService.save(adopter);
    } catch (Exception e) {
      logger.error("Error while saving adopter registration data.", e);
      return Response.serverError().build();
    }
    return Response.ok().build();
  }

  @POST
  @Path("registration/finalize")
  @Operation(
      summary = "Finalize the registration",
      description = "Finalizes the registration and starts sending data."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Registration finalized."),
      @ApiResponse(responseCode = "500", description = "Couldn't save the finalized registration.")
  })
  public Response register() {
    logger.debug("Finalizing adopter registration.");

    Adopter adopter = (Adopter) registrationService.get();
    adopter.setRegistered(true);

    try {
      registrationService.save(adopter);
    } catch (Exception e) {
      logger.error("Error while saving adopter registration data.", e);
      return Response.serverError().build();
    }
    return Response.ok().build();
  }

  @GET
  @Produces(MediaType.TEXT_PLAIN)
  @Path("isUpToDate")
  @Operation(
      summary = "Check whether the registration is up to date",
      description = "Returns true if the registration data was modified within the last 7 days, i.e. the "
          + "registration is up to date"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "true if the registration data was modified within the last 7 days, false otherwise"
      )
  })
  public Response isUpToDate() {
    Adopter data = (Adopter) registrationService.get();
    Calendar cal = Calendar.getInstance();
    cal.add(Calendar.DAY_OF_MONTH, -7);
    //A fresh install might have no data at all, so we null check everything
    if (data != null && data.getDateModified() != null && data.getDateModified().after(cal.getTime())) {
      return Response.ok("true").build();
    }
    return Response.ok("false").build();
  }

  @DELETE
  @Path("registration")
  @Operation(
      summary = "Delete the adopter registration data",
      description = "Deletes the adopter registration data"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Successful deleted form data."),
      @ApiResponse(responseCode = "500", description = "Error while deleting adopter registration data.")
  })
  public Response deleteRegistrationData() {
    logger.debug("Deleting adopter registration data.");
    try {
      registrationService.markForDeletion();
      return ok();
    } catch (Exception e) {
      logger.error("Error while deleting adopter registration data.", e);
      return serverError();
    }
  }

  @GET
  @Produces(MediaType.TEXT_PLAIN)
  @Path("latestToU")
  @Operation(
      summary = "Get the latest terms of use version",
      description = "Gets the latest terms of use version."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The name of the latest terms of use version.")
  })
  public String getLatestTermsofUse() {
    return Adopter.getLatestTermsOfUse().name();
  }

}
