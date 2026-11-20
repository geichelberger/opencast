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

package org.opencastproject.serviceregistry.impl.endpoint;

import static javax.ws.rs.core.Response.Status.INTERNAL_SERVER_ERROR;
import static org.opencastproject.util.RestUtil.R.badRequest;
import static org.opencastproject.util.RestUtil.R.ok;
import static org.opencastproject.util.RestUtil.getResponseType;

import org.opencastproject.job.api.Incident;
import org.opencastproject.job.api.Incident.Severity;
import org.opencastproject.job.api.IncidentTree;
import org.opencastproject.job.api.JaxbIncident;
import org.opencastproject.job.api.JaxbIncidentDigestList;
import org.opencastproject.job.api.JaxbIncidentFullList;
import org.opencastproject.job.api.JaxbIncidentFullTree;
import org.opencastproject.job.api.JaxbIncidentList;
import org.opencastproject.job.api.JaxbIncidentTree;
import org.opencastproject.job.api.Job;
import org.opencastproject.job.api.JobParser;
import org.opencastproject.rest.RestConstants;
import org.opencastproject.serviceregistry.api.IncidentL10n;
import org.opencastproject.serviceregistry.api.IncidentService;
import org.opencastproject.serviceregistry.api.IncidentServiceException;
import org.opencastproject.serviceregistry.api.ServiceRegistry;
import org.opencastproject.systems.OpencastConstants;
import org.opencastproject.util.DateTimeSupport;
import org.opencastproject.util.GsonUtil;
import org.opencastproject.util.LocalHashMap;
import org.opencastproject.util.NotFoundException;
import org.opencastproject.util.UrlSupport;
import org.opencastproject.util.data.Tuple;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import org.apache.commons.lang3.LocaleUtils;
import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

/** REST endpoint for Incident Service. */
@Path("/incidents")
@Tag(
    name = "Incident Service",
    description = "This service creates, edits and retrieves and helps managing incidents."
)
@Component(
    property = {
      "service.description=Incident Service REST Endpoint",
      "opencast.service.type=org.opencastproject.incident",
      "opencast.service.path=/incidents"
    },
    immediate = true,
    service = { IncidentServiceEndpoint.class }
)
@JaxrsResource
public class IncidentServiceEndpoint {
  /** Logging utility */
  private static final Logger logger = LoggerFactory.getLogger(IncidentServiceEndpoint.class);

  public static final String FMT_FULL = "full";
  public static final String FMT_DIGEST = "digest";
  public static final String FMT_SYS = "sys";
  private static final String FMT_DEFAULT = FMT_SYS;

  /** The incident service */
  protected IncidentService svc;

  /** The remote service manager */
  protected ServiceRegistry serviceRegistry = null;

  /** This server's base URL */
  protected String serverUrl = UrlSupport.DEFAULT_BASE_URL;

  /** The REST endpoint's base URL */
  protected String serviceUrl = "/incidents";

  /** OSGi callback for setting the incident service. */
  @Reference
  public void setIncidentService(IncidentService incidentService) {
    this.svc = incidentService;
  }

  /**
   * The method that is called, when the service is activated
   *
   * @param cc
   *         The ComponentContext of this service
   */
  public void activate(ComponentContext cc) {
    // Get the configured server URL
    if (cc != null) {
      String ccServerUrl = cc.getBundleContext().getProperty(OpencastConstants.SERVER_URL_PROPERTY);
      if (StringUtils.isNotBlank(ccServerUrl)) {
        serverUrl = ccServerUrl;
      }
      serviceUrl = (String) cc.getProperties().get(RestConstants.SERVICE_PATH_PROPERTY);
    }
  }

  @GET
  @Produces({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
  @Path("job/incidents.{type:xml|json}")
  @Operation(
      summary = "Get the incidents of jobs",
      description = "Returns the job incidents with the given identifiers."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The job incidents.")
  })
  public Response getIncidentsOfJobAsList(
      @Context HttpServletRequest request,
      @Parameter(description = "The job identifiers.", required = true)
      @QueryParam("id") final List<Long> jobIds,
      @Parameter(description = "The response format [full|digest|sys]. Defaults to sys", example = "sys")
      @QueryParam("format") @DefaultValue(FMT_DEFAULT) final String format,
      @Parameter(description = "The media type of the response [xml|json]", required = true, example = "xml")
      @PathParam("type") final String type
  ) {
    try {
      final List<Incident> incidents = svc.getIncidentsOfJob(jobIds);
      final MediaType mt = getResponseType(type);
      if (Objects.equals(FMT_SYS, format)) {
        return ok(mt, new JaxbIncidentList(incidents));
      } else if (Objects.equals(FMT_DIGEST, format)) {
        return ok(mt, new JaxbIncidentDigestList(svc, request.getLocale(), incidents));
      } else if (Objects.equals(FMT_FULL, format)) {
        return ok(mt, new JaxbIncidentFullList(svc, request.getLocale(), incidents));
      } else {
        return unknownFormat();
      }
    } catch (NotFoundException e) {
      // should not happen
      logger.error("Unable to get job incident! Consistency issue!", e);
      throw new WebApplicationException(e, INTERNAL_SERVER_ERROR);
    } catch (IncidentServiceException e) {
      logger.warn("Unable to get job incident for id {}: {}", jobIds, e.getMessage());
      throw new WebApplicationException(INTERNAL_SERVER_ERROR);
    }
  }

  @GET
  @Produces({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
  @Path("job/{id}.{type:xml|json}")
  @Operation(
      summary = "Get the incidents of a job",
      description = "Returns the job incident for the job with the given identifier."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The job incident."),
      @ApiResponse(responseCode = "404", description = "No job incident with this identifier was found.")
  })
  public Response getIncidentsOfJobAsTree(
      @Context HttpServletRequest request,
      @Parameter(description = "The job identifier.", required = true)
      @PathParam("id") final long jobId,
      @Parameter(description = "Whether to show the cascaded incidents.", example = "false")
      @QueryParam("cascade") @DefaultValue("false") boolean cascade,
      @Parameter(description = "The response format [full|digest|sys]. Defaults to sys", example = "sys")
      @QueryParam("format") @DefaultValue(FMT_DEFAULT) final String format,
      @Parameter(description = "The media type of the response [xml|json]", required = true, example = "xml")
      @PathParam("type") final String type
  ) throws NotFoundException {
    try {
      final IncidentTree tree = svc.getIncidentsOfJob(jobId, cascade);
      final MediaType mt = getResponseType(type);
      if (Objects.equals(FMT_SYS, format)) {
        return ok(mt, new JaxbIncidentTree(tree));
      } else if (Objects.equals(FMT_DIGEST, format)) {
        return ok(mt, new JaxbIncidentFullTree(svc, request.getLocale(), tree));
      } else if (Objects.equals(FMT_FULL, format)) {
        return ok(mt, new JaxbIncidentFullTree(svc, request.getLocale(), tree));
      } else {
        return unknownFormat();
      }
    } catch (IncidentServiceException e) {
      logger.warn("Unable to get job incident for id {}: {}", jobId, e.getMessage());
      throw new WebApplicationException(INTERNAL_SERVER_ERROR);
    }
  }

  @GET
  @Produces({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
  @Path("{id}.{type:xml|json}")
  @Operation(
      summary = "Get an incident",
      description = "Returns the job incident by it's incident identifier."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The job incident."),
      @ApiResponse(responseCode = "404", description = "No job incident with this identifier was found.")
  })
  public Response getIncident(
      @Parameter(description = "The incident identifier.", required = true)
      @PathParam("id") final long incidentId,
      @Parameter(description = "The media type of the response [xml|json]", required = true, example = "xml")
      @PathParam("type") final String type
  ) throws NotFoundException {
    try {
      Incident incident = svc.getIncident(incidentId);
      return ok(getResponseType(type), new JaxbIncident(incident));
    } catch (IncidentServiceException e) {
      logger.warn("Unable to get job incident for incident id {}", incidentId, e);
      throw new WebApplicationException(INTERNAL_SERVER_ERROR);
    }
  }

  @GET
  @SuppressWarnings("unchecked")
  @Produces(MediaType.APPLICATION_JSON)
  @Path("localization/{id}")
  @Operation(
      summary = "Get the localization of an incident",
      description = "Returns the localization of an incident by it's id as JSON"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The localization of the given job incidents."),
      @ApiResponse(responseCode = "404", description = "No job incident with this incident identifier was found.")
  })
  public Response getLocalization(
      @Parameter(description = "The incident identifiers.", required = true)
      @PathParam("id") final long incidentId,
      @Parameter(description = "The locale.", required = true)
      @QueryParam("locale") String locale
  ) throws NotFoundException {
    try {
      IncidentL10n localization = svc.getLocalization(incidentId, LocaleUtils.toLocale(locale));
      JsonObject json = new JsonObject();
      json.addProperty("title", localization.getTitle());
      json.addProperty("description", localization.getDescription());
      return Response.ok(json.toString()).build();
    } catch (IncidentServiceException e) {
      logger.warn("Unable to get job localization of jo incident:", e);
      throw new WebApplicationException(INTERNAL_SERVER_ERROR);
    }
  }

  @POST
  @Produces(MediaType.APPLICATION_XML)
  @Path("/")
  @Operation(
      summary = "Create an incident",
      description = "Creates a new job incident and returns it as XML"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "201", description = "New job incident has been created"),
      @ApiResponse(responseCode = "400", description = "Unable to parse the one of the form params"),
      @ApiResponse(responseCode = "409", description = "No job incident related job exists")
  })
  public Response postIncident(
      @Parameter(description = "The job on where to create the incident", required = true)
      @FormParam("job") String jobXml,
      @Parameter(description = "The incident creation date", required = true)
      @FormParam("date") String date,
      @Parameter(description = "The incident error code", required = true)
      @FormParam("code") String code,
      @Parameter(description = "The incident error code", required = true)
      @FormParam("severity") String severityString,
      @Parameter(description = "The incident details")
      @FormParam("details") String details,
      @Parameter(description = "The incident parameters")
      @FormParam("params") LocalHashMap params
  ) {
    Job job;
    Date timestamp;
    Severity severity;
    Map<String, String> map = new HashMap<String, String>();
    List<Tuple<String, String>> list = new ArrayList<Tuple<String, String>>();
    try {
      job = JobParser.parseJob(jobXml);
      timestamp = new Date(DateTimeSupport.fromUTC(date));
      severity = Severity.valueOf(severityString);
      if (params != null) {
        map = params.getMap();
      }
      if (StringUtils.isNotBlank(details)) {
        final JsonArray array = GsonUtil.gson().fromJson(details, JsonArray.class);
        for (JsonElement element : array) {
          JsonObject tuple = element.getAsJsonObject();
          list.add(Tuple.tuple(GsonUtil.getStringOrNull(tuple, "title"),
                  GsonUtil.getStringOrNull(tuple, "content")));
        }
      }
    } catch (Exception e) {
      return Response.status(Status.BAD_REQUEST).entity(e.getMessage()).build();
    }

    try {
      Incident incident = svc.storeIncident(job, timestamp, code, severity, map, list);
      String uri = UrlSupport.concat(serverUrl, serviceUrl, Long.toString(incident.getId()), ".xml");
      return Response.created(new URI(uri)).entity(new JaxbIncident(incident)).build();
    } catch (IllegalStateException e) {
      return Response.status(Status.CONFLICT).build();
    } catch (Exception e) {
      logger.warn("Unable to post incident for job {}", job.getId(), e);
      throw new WebApplicationException(INTERNAL_SERVER_ERROR);
    }
  }

  private Response unknownFormat() {
    return badRequest("Unknown format");
  }
}
