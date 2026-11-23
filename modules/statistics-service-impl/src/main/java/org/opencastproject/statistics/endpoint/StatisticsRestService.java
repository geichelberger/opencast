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

package org.opencastproject.statistics.endpoint;


import org.opencastproject.statistics.api.DataResolution;
import org.opencastproject.statistics.api.StatisticsProvider;
import org.opencastproject.statistics.api.StatisticsService;
import org.opencastproject.statistics.api.TimeSeries;
import org.opencastproject.statistics.api.TimeSeriesProvider;
import org.opencastproject.util.NotFoundException;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import javax.ws.rs.GET;
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
 * REST endpoint for Statistics Service.
 *
 */
@Path("/statistics")
@Tag(
    name = "Statistics Service",
    description = "This service provides statistics."
)
@Component(
    immediate = true,
    service = StatisticsRestService.class,
    property = {
        "service.description=Statistics REST Endpoint",
        "opencast.service.type=org.opencastproject.statistics",
        "opencast.service.path=/statistics"
    }
)
@JaxrsResource
public class StatisticsRestService {

  /** Logging utility */
  private static final Logger logger = LoggerFactory.getLogger(StatisticsRestService.class);

  /** Statistics Service */
  private StatisticsService statisticsService;

  /**
   * OSGi callback for setting statistics service.
   *
   * @param statisticsService
   */
  @Reference
  public void setService(StatisticsService statisticsService) {
    this.statisticsService = statisticsService;
  }

  /**
   * Activates REST service (needed by OSGi)
   *
   * @param cc
   *          ComponentContext
   */
  @Activate
  public void activate(ComponentContext cc) {
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("writeDuration")
  @Operation(
      summary = "Write a duration",
      description = "Writes a duration"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "Writing worked. The response body is the text NO_CONTENT instead of an empty response."
      ),
      @ApiResponse(responseCode = "500", description = "The duration could not be written.")
  })
  public Response writeDuration(
      @Parameter(description = "Organization ID of the data point")
      @QueryParam("organizationId") final String organizationId,
      @Parameter(description = "Measurement name of the data point")
      @QueryParam("measurementName") final String measurementName,
      @Parameter(description = "Retention policy of the data point")
      @QueryParam("retentionPolicy") final String retentionPolicy,
      @Parameter(description = "Resource name for the organization")
      @QueryParam("organizationIdResourceName") final String organizationIdResourceName,
      @Parameter(description = "Field name to write")
      @QueryParam("fieldName") final String fieldName,
      @Parameter(description = "The temporal resolution to store it in")
      @QueryParam("temporalResolution") final String temporalResolution,
      @Parameter(description = "The actual duration to write")
      @QueryParam("duration") final String duration
  ) {
    try {
      statisticsService
              .writeDuration(organizationId, measurementName, retentionPolicy, organizationIdResourceName, fieldName,
                      TimeUnit.valueOf(temporalResolution), Duration.parse(duration));
      return Response.ok(Response.Status.NO_CONTENT).build();
    } catch (Exception e) {
      logger.error("Could not retrieve providers: {}", e.getMessage());
      throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("providers.json")
  @Operation(
      summary = "List the active providers",
      description = "Returns active providers"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The active providers."),
      @ApiResponse(responseCode = "500", description = "The providers could not be retrieved.")
  })
  public Response getProviders() {
    try {
      return Response.ok(providersToJson(statisticsService.getProviders()).toString()).build();
    } catch (Exception e) {
      logger.error("Could not retrieve providers: {}", e.getMessage());
      throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("timeseries/{providerId:.+}.json")
  @Operation(
      summary = "Get the time series data of a provider",
      description = "Returns the time series data for the given providerId"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The time series data."),
      @ApiResponse(responseCode = "500", description = "The time series data could not be retrieved.")
  })
  public Response getTimeSeriesData(
      @Parameter(description = "The provider identifier", required = true)
      @PathParam("providerId") final String providerId,
      @Parameter(description = "The id of the resource to get the data for. E.g. episode id.", required = true)
      @QueryParam("resourceId") final String resourceId,
      @Parameter(description = "Start of the time series as ISO 8601 UTC date string", required = true)
      @QueryParam("from") final String from,
      @Parameter(description = "End of the time series as ISO 8601 UTC date string", required = true)
      @QueryParam("to") final String to,
      @Parameter(
          description = "Data aggregation level. Must be one of 'daily', 'weekly', 'monthly', 'yearly'",
          required = true
      )
      @QueryParam("resolution") final String resolution,
      @Parameter(description = "The time zone id to use for calculations", required = true)
      @QueryParam("zoneId") final String zoneId
  ) {
    try {
      final TimeSeries timeSeries = statisticsService.getTimeSeriesData(
          statisticsService.getProvider(providerId).orElseThrow(NotFoundException::new),
          resourceId,
          Instant.parse(from),
          Instant.parse(to),
          DataResolution.fromString(resolution),
          ZoneId.of(zoneId)
      );
      return Response.ok(timeSeriesToJson(timeSeries).toString()).build();
    } catch (Exception e) {
      logger.error("Could not retrieve time series data for provider {}: {}", providerId, e.getMessage());
      throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  private static JsonObject timeSeriesToJson(final TimeSeries timeSeries) {
    final JsonObject json = new JsonObject();
    final JsonArray jsonLabels = new JsonArray();
    final JsonArray jsonValues = new JsonArray();
    for (int i = 0; i < timeSeries.getValues().size(); i++) {
      jsonLabels.add(timeSeries.getLabels().get(i));
      jsonValues.add(timeSeries.getValues().get(i));
    }
    json.add("labels", jsonLabels);
    json.add("values", jsonValues);
    if (timeSeries.getTotal().isPresent()) {
      json.addProperty("total", timeSeries.getTotal().getAsDouble());
    }
    return json;
  }

  private static JsonArray providersToJson(final Set<StatisticsProvider> providers) {
    final JsonArray json = new JsonArray();
    for (StatisticsProvider provider : providers) {
      final JsonObject jsonProvider = new JsonObject();
      final JsonArray jsonResolutions = new JsonArray();
      jsonProvider.addProperty("id", provider.getId());
      jsonProvider.addProperty("title", provider.getTitle());
      jsonProvider.addProperty("description", provider.getDescription());
      jsonProvider.addProperty("resourceType", provider.getResourceType().name());
      if (provider instanceof TimeSeriesProvider) {
        for (DataResolution resolution : ((TimeSeriesProvider) provider).getDataResolutions()) {
          jsonResolutions.add(resolution.name());
        }
        jsonProvider.add("dataResolutions", jsonResolutions);
      }
      json.add(jsonProvider);
    }
    return json;
  }
}
