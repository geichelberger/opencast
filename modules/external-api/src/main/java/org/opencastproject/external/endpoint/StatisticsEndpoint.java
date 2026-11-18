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

import static org.opencastproject.util.data.functions.Misc.chuck;

import org.opencastproject.external.common.ApiMediaType;
import org.opencastproject.external.common.ApiResponseBuilder;
import org.opencastproject.external.util.statistics.QueryUtils;
import org.opencastproject.external.util.statistics.ResourceTypeUtils;
import org.opencastproject.external.util.statistics.StatisticsProviderUtils;
import org.opencastproject.index.service.api.IndexService;
import org.opencastproject.opensearch.api.SearchIndexException;
import org.opencastproject.opensearch.index.OpenSearchIndex;
import org.opencastproject.opensearch.index.objects.event.Event;
import org.opencastproject.opensearch.index.objects.series.Series;
import org.opencastproject.security.api.Organization;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.security.api.UnauthorizedException;
import org.opencastproject.security.api.User;
import org.opencastproject.security.util.SecurityUtil;
import org.opencastproject.statistics.api.ResourceType;
import org.opencastproject.statistics.api.StatisticsProvider;
import org.opencastproject.statistics.api.StatisticsService;
import org.opencastproject.statistics.export.api.StatisticsExportService;
import org.opencastproject.util.NotFoundException;
import org.opencastproject.util.RestUtil;

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

import java.time.ZoneId;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

@Path("/api/statistics")
@Produces({ ApiMediaType.JSON, ApiMediaType.VERSION_1_3_0, ApiMediaType.VERSION_1_4_0, ApiMediaType.VERSION_1_5_0,
            ApiMediaType.VERSION_1_6_0, ApiMediaType.VERSION_1_7_0, ApiMediaType.VERSION_1_8_0,
            ApiMediaType.VERSION_1_9_0, ApiMediaType.VERSION_1_10_0, ApiMediaType.VERSION_1_11_0,
            ApiMediaType.VERSION_1_12_0 })
@Tag(name = "External API")
@Tag(
    name = "External API - Statistics",
    description = "Provides statistics"
)
@Component(
    immediate = true,
    service = StatisticsEndpoint.class,
    property = {
        "service.description=External API - Statistics Endpoint",
        "opencast.service.type=org.opencastproject.external.statistics",
        "opencast.service.path=/api/statistics"
    }
)
@JaxrsResource
public class StatisticsEndpoint {

  /** The logging facility */
  private static final Logger logger = LoggerFactory.getLogger(StatisticsEndpoint.class);

  private SecurityService securityService;
  private IndexService indexService;
  private OpenSearchIndex opensearchIndex;
  private StatisticsService statisticsService;
  private StatisticsExportService statisticsExportService;

  @Reference
  public void setSecurityService(SecurityService securityService) {
    this.securityService = securityService;
  }

  @Reference
  public void setIndexService(IndexService indexService) {
    this.indexService = indexService;
  }

  @Reference
  public void setOpenSearchIndex(OpenSearchIndex opensearchIndex) {
    this.opensearchIndex = opensearchIndex;
  }

  @Reference
  public void setStatisticsService(StatisticsService statisticsService) {
    this.statisticsService = statisticsService;
  }

  @Reference
  public void setStatisticsExportService(StatisticsExportService statisticsExportService) {
    this.statisticsExportService = statisticsExportService;
  }

  /** OSGi activation method */
  @Activate
  void activate(ComponentContext cc) {
    logger.info("Activating External API - Statistics Endpoint");
  }

  @GET
  @Path("providers")
  @Operation(
      summary = "Get statistics providers",
      description = "Returns a list of available statistics providers"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returns the requested statistics providers as JSON"),
      @ApiResponse(responseCode = "401", description = "If the current user is not authorized to perform this action")
  })
  public Response getProviders(
      @HeaderParam("Accept") String acceptHeader,
      @Parameter(description = "Usage [Filter Name]:[Value to Filter With]. Available filter: \"resourceType\"")
      @QueryParam("filter") String filter,
      @Parameter(description = "Whether the parameters should be included in the response.")
      @QueryParam("withparameters") Boolean withParameters
  ) {

    ResourceType resourceType = null;

    if (StringUtils.isNotBlank(filter)) {
      for (String f : filter.split(",")) {
        String[] filterTuple = f.split(":");
        if (filterTuple.length != 2) {
          logger.debug("No value for filter {} in filters list: {}", filterTuple[0], filter);
          continue;
        }
        String name = filterTuple[0];
        String value = f.substring(name.length() + 1);

        if ("resourceType".equals(name)) {
          try {
            resourceType = ResourceTypeUtils.fromString(value);
          } catch (IllegalArgumentException e) {
            return RestUtil.R.badRequest("Invalid value for 'resourceType'");
          }
        } else {
          logger.warn("Unknown filter criteria {}", name);
          return RestUtil.R.badRequest("Unknown filter");
        }
      }
    }

    Set<StatisticsProvider> providers;
    if (resourceType != null) {
      providers = statisticsService.getProviders(resourceType);
    } else {
      providers = statisticsService.getProviders();
    }

    JsonArray result = new JsonArray();
    providers.stream().map(p -> StatisticsProviderUtils.toJson(p, withParameters)).forEach(result::add);

    return ApiResponseBuilder.Json.ok(acceptHeader, result.toString());
  }

  @GET
  @Path("providers/{providerId}")
  @Operation(
      summary = "Get a statistics provider",
      description = "Returns the statistics provider with the specified id"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returns the requested statistics provider as JSON")
  })
  public Response getProvider(
      @HeaderParam("Accept") String acceptHeader,
      @Parameter(description = "The identifier of the statistics provider", required = true)
      @PathParam("providerId") String id,
      @Parameter(description = "Whether the parameters should be included in the response.")
      @QueryParam("withparameters") Boolean withParameters
  ) {

    if (StringUtils.isNotBlank(id)) {
      Optional<StatisticsProvider> provider = statisticsService.getProvider(id);
      if (provider.isPresent()) {
        return ApiResponseBuilder.Json.ok(acceptHeader, StatisticsProviderUtils.toJson(provider.get(),
            withParameters).toString());
      } else {
        return ApiResponseBuilder.notFound("Cannot find a statistics provider with id '%s'.", id);
      }
    } else {
      return RestUtil.R.badRequest("Invalid value for providerId");
    }
  }

  @POST
  @Path("data/query")
  @Operation(
      summary = "Query statistical data",
      description = "Returns the statistical data based on the query posted"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "Returns the statistical data as requested by the query as JSON array"
      ),
      @ApiResponse(responseCode = "401", description = "If the current user is not authorized to perform this action")
  })
  public Response getStatistics(
      @HeaderParam("Accept") String acceptHeader,
      @Parameter(description = "An JSON array describing the queries to be executed", required = true)
      @FormParam("data") String data
  ) {

    List<QueryUtils.Query> queries = null;
    try {
      queries = QueryUtils.parse(data, statisticsService);
    } catch (Exception e) {
      logger.debug("Unable to parse form parameter 'data' {}, exception", data, e);
      return RestUtil.R.badRequest("Unable to parse form parameter 'data': " + e.getMessage());
    }

    JsonArray result = new JsonArray();
    queries.stream()
      .peek(query -> checkAccess(query.getParameters().getResourceId(), query.getProvider().getResourceType()))
      .map(query -> QueryUtils.execute(query))
        .forEach(result::add);

    return ApiResponseBuilder.Json.ok(acceptHeader, result.toString());
  }

  @POST
  @Produces({ ApiMediaType.JSON, ApiMediaType.VERSION_1_4_0, ApiMediaType.VERSION_1_5_0, ApiMediaType.VERSION_1_6_0,
              ApiMediaType.VERSION_1_7_0, ApiMediaType.VERSION_1_8_0, ApiMediaType.VERSION_1_9_0 })
  @Path("data/export.csv")
  @Operation(
      summary = "Export statistical data as CSV",
      description = "Returns a statistics csv export"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returns the csv data as requested by the query as plain text"),
      @ApiResponse(responseCode = "401", description = "If the current user is not authorized to perform this action")
  })
  public Response getExportCSV(
      @HeaderParam("Accept") String acceptHeader,
      @Parameter(description = "A JSON object describing the query to be executed", required = true)
      @FormParam("data") String data,
      @Parameter(description = "Limit for pagination.")
      @FormParam("limit") Integer limit,
      @Parameter(description = "Offset for pagination.")
      @FormParam("offset") Integer offset,
      @Parameter(
          description = "Usage [Filter Name]:[Value to Filter With]. Multiple filters can be used "
              + "by combining them with commas \",\"."
      )
      @FormParam("filter") String filter
  ) throws NotFoundException, SearchIndexException, UnauthorizedException {

    final int lim = limit != null ? Math.max(0, limit) : 0;
    final int off = offset != null ? Math.max(0, offset) : 0;

    final Map<String, String> filters = Arrays.stream(Optional.ofNullable(filter).orElse("")
            .split(","))
            .filter(f -> f.contains(":"))
            .collect(Collectors.toMap(
                    f -> f.substring(0, f.indexOf(":")),
                    f -> f.substring(f.indexOf(":") + 1)));

    QueryUtils.Query query = null;
    try {
      query = QueryUtils.parseQuery(data, statisticsService);
    } catch (Exception e) {
      logger.debug("Unable to parse form parameter 'data' {}, exception", data, e);
      return RestUtil.R.badRequest("Unable to parse form parameter 'data': " + e.getMessage());
    }
    checkAccess(query.getParameters().getResourceId(), query.getProvider().getResourceType());

    final QueryUtils.ExportParameters parameters = (QueryUtils.ExportParameters) query.getParameters();
    final String result = statisticsExportService.getCSV(
            query.getProvider(),
            parameters.getResourceId(),
            parameters.getFrom(),
            parameters.getTo(),
            parameters.getDataResolution(),
            this.opensearchIndex,
            ZoneId.systemDefault(),
            true,
            parameters.getDetailLevel(),
            lim,
            off,
            filters
    );

    JsonObject csvJson = new JsonObject();
    csvJson.addProperty("csv", result);
    return ApiResponseBuilder.Json.ok(acceptHeader, csvJson.toString());
  }

  private void checkAccess(final String resourceId, final ResourceType resourceType) {
    try {
      switch (resourceType) {
        case EPISODE:
          checkMediapackageAccess(resourceId);
          break;
        case SERIES:
          checkSeriesAccess(resourceId);
          break;
        case ORGANIZATION:
          checkOrganizationAccess(resourceId);
          break;
        default:
          break;
      }
    } catch (UnauthorizedException | SearchIndexException e) {
      chuck(e);
    }
  }

  private void checkMediapackageAccess(final String mpId) throws UnauthorizedException, SearchIndexException {
    final Optional<Event> event = indexService.getEvent(mpId, opensearchIndex);
    if (event.isEmpty()) {
      // IndexService checks permissions and returns None if user is unauthorized
      throw new UnauthorizedException(securityService.getUser(), "read");
    }
  }

  private void checkSeriesAccess(final String seriesId) throws UnauthorizedException, SearchIndexException {
    final Optional<Series> series = opensearchIndex.getSeries(seriesId, securityService.getOrganization(),
        securityService.getUser());
    if (series.isEmpty()) {
      // IndexService checks permissions and returns None if user is unauthorized
      throw new UnauthorizedException(securityService.getUser(), "read");
    }
  }

  private void checkOrganizationAccess(final String orgId) throws UnauthorizedException {
    final User currentUser = securityService.getUser();
    final Organization currentOrg = securityService.getOrganization();
    final String currentOrgId = currentOrg.getId();

    boolean authorized = SecurityUtil.isGlobalAdmin(currentUser)
            || (currentOrgId.equals(orgId) && SecurityUtil.isOrganizationAdmin(currentUser, currentOrg));

    if (!authorized) {
      throw new UnauthorizedException(currentUser, "read");
    }
  }

}
