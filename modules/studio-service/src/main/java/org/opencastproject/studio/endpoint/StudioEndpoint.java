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

package org.opencastproject.studio.endpoint;


import org.opencastproject.opensearch.api.SearchIndexException;
import org.opencastproject.opensearch.api.SearchResultItem;
import org.opencastproject.opensearch.index.OpenSearchIndex;
import org.opencastproject.opensearch.index.objects.series.SeriesSearchQuery;
import org.opencastproject.security.api.Permissions;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.studio.endpoint.dto.SeriesDto;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.stream.Collectors;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
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

@Path("/studio-api")
@Tag(
    name = "Studio REST Endpoint",
    description = "The Internal studio API is not stable!"
)
@Component(
    immediate = true,
    service = StudioEndpoint.class,
    property = {
        "service.description=Studio REST Endpoint",
        "opencast.service.type=org.opencastproject.studio",
        "opencast.service.path=/studio-api"
    }
)
@JaxrsResource
public class StudioEndpoint {

  private static final Logger logger = LoggerFactory.getLogger(StudioEndpoint.class);

  private final Gson gson;

  private OpenSearchIndex opensearchIndex;
  private SecurityService securityService;

  {
    gson = new GsonBuilder().serializeNulls().create();
  }

  @GET
  @Path("/series.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the series the current user can write to",
      description = "Returns all series for which the current user has write permissions."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returns a list of series.")
  })
  public Response getSeries(
      @Parameter(
          description = "Usage <Filter Name>:<Value to Filter With>. Filters can combine using a comma \",\"."
              + " Available Filters: title, textFilter."
      )
      @QueryParam("filter") String filter
  ) {
    SeriesSearchQuery query = new SeriesSearchQuery(securityService.getOrganization().getId(),
        securityService.getUser());
    query.withoutActions();
    query.withAction(Permissions.Action.WRITE);

    if (filter != null && !filter.isBlank()) {
      for (String f : filter.split(",")) {
        String[] filterTuple = f.split(":", 2);
        if (filterTuple.length < 2) {
          throw new WebApplicationException(Response
              .status(Response.Status.BAD_REQUEST)
              .entity(String.format("Filter %s is not valid: %s", filterTuple[0], filter))
              .build());
        }
        String name = filterTuple[0];
        String value = filterTuple[1];

        if ("title".equals(name)) {
          query.withTitle(value);
        } else if ("textFilter".equals(name)) {
          query.withText("*" + value + "*");
        } else {
          throw new WebApplicationException(Response
              .status(Response.Status.BAD_REQUEST)
              .entity(String.format("Unknown filter criteria %s", name))
              .build());
        }
      }
    }

    try {
      var items = Arrays.stream(opensearchIndex.getByQuery(query).getItems())
              .map(SearchResultItem::getSource)
              .map(SeriesDto::create)
              .collect(Collectors.toList());
      return Response.ok(gson.toJson(items)).build();
    } catch (SearchIndexException e) {
      throw new WebApplicationException(e);
    }

  }

  @Reference
  public void setOpenSearchIndex(OpenSearchIndex opensearchIndex) {
    this.opensearchIndex = opensearchIndex;
  }

  @Reference
  public void setSecurityService(SecurityService securityService) {
    this.securityService = securityService;
  }
}
