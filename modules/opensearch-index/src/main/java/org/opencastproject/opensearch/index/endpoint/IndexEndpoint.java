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

package org.opencastproject.opensearch.index.endpoint;

import org.opencastproject.opensearch.index.OpenSearchIndex;
import org.opencastproject.opensearch.index.rebuild.IndexProducer;
import org.opencastproject.opensearch.index.rebuild.IndexRebuildService;
import org.opencastproject.opensearch.index.rebuild.IndexRebuildService.DataType;
import org.opencastproject.opensearch.index.rebuild.IndexRebuildService.Service;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.security.util.SecurityContext;
import org.opencastproject.util.RestUtil.R;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import org.apache.commons.lang3.EnumUtils;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * The index endpoint allows the management of the opensearch index.
 */
@Path("/index")
@Tag(
    name = "Index Endpoint",
    description = "Provides operations related to the index that serves both the Admin UI and the External API"
)
@Component(
        immediate = true,
        property = {
                "service.description=Index Endpoint",
                "opencast.service.type=org.opencastproject.opensearch.index.endpoint",
                "opencast.service.path=/index"
        },
        service = { IndexEndpoint.class }
)
@JaxrsResource
public class IndexEndpoint {

  /** The logging facility */
  private static final Logger logger = LoggerFactory.getLogger(IndexEndpoint.class);

  /** The executor service */
  private final ExecutorService executor = Executors.newSingleThreadExecutor();

  /** The index */
  private OpenSearchIndex opensearchIndex;

  /** The security service */
  protected SecurityService securityService = null;

  /** The index rebuild service **/
  private IndexRebuildService indexRebuildService = null;

  @Reference
  public void setOpenSearchIndex(OpenSearchIndex opensearchIndex) {
    this.opensearchIndex = opensearchIndex;
  }

  @Reference
  public void setIndexRebuildService(IndexRebuildService indexRebuildService) {
    this.indexRebuildService = indexRebuildService;
  }

  @Reference
  public void setSecurityService(SecurityService securityService) {
    this.securityService = securityService;
  }

  @Activate
  public void activate() {
    logger.info("Activate IndexEndpoint");
  }

  @POST
  @Path("clear")
  @Operation(
      summary = "Clear the index",
      description = "Clear the index"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Index is cleared"),
      @ApiResponse(responseCode = "500", description = "Unable to clear index")
  })
  public Response clearIndex() {
    final SecurityContext securityContext = new SecurityContext(securityService, securityService.getOrganization(),
        securityService.getUser());
    return securityContext.runInContext(() -> {
      try {
        logger.info("Clear the index");
        opensearchIndex.clear();
        indexRebuildService.getIndexProducer(Service.Search).clear();
        return R.ok();
      } catch (Throwable t) {
        logger.error("Clearing the index failed", t);
        return R.serverError();
      }
    });
  }

  @POST
  @Path("rebuild/{service}")
  @Operation(
      summary = "Rebuild the index from a service",
      description = "Repopulates the Index from a specific service"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "OK if repopulation has started")
  })
  public Response partiallyRebuildIndex(
      @Parameter(
          description = "The service to recreate index from. "
              + "The available services are: Series, Scheduler, AssetManager, Comments, Workflow and Search. "
              + "The service order (see above) is very important except for Search! Make sure, you do not run index "
              + "rebuild"
              + "for more than one service at a time!",
          required = true
      )
      @PathParam("service") final String serviceStr
  ) {
    Service service = EnumUtils.getEnum(Service.class, serviceStr);
    if (service == null) {
      return R.badRequest("The given path param for service was invalid.");
    }
    IndexProducer indexProducer = indexRebuildService.getIndexProducer(service);

    final SecurityContext securityContext = new SecurityContext(securityService, securityService.getOrganization(),
        securityService.getUser());
    executor.execute(() -> securityContext.runInContext(() -> {
      try {
        logger.info("Starting to repopulate the index from service {}", service);
        indexRebuildService.rebuildIndex(indexProducer, DataType.ALL);
      } catch (Throwable t) {
        logger.error("Repopulating the index failed", t);
      }
    }));
    return R.ok();
  }

  @POST
  @Path("rebuild/{service}/{type}")
  @Operation(
      summary = "Rebuild the index from a service for one type of data",
      description = "Repopulates the index for a specific service, but only for a specific type of data "
          + "in order to save time. "
          + "Only use this endpoint if you have been explicitly told to or know what you are doing, else you risk "
          + "inconsistent data in the index!"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "OK if repopulation has started"),
      @ApiResponse(responseCode = "400", description = "If the given parameters aren't one of the supported values")
  })
  public Response partiallyRebuildIndexByType(
      @Parameter(
          description = "The service to recreate index from. The available services are: AssetManager. ",
          required = true
      )
      @PathParam("service") final String serviceStr,
      @Parameter(description = "The type of data to re-index. The available types are: ACL. ", required = true)
      @PathParam("type") final String dataTypeStr
  ) {
    Service service = EnumUtils.getEnum(Service.class, serviceStr);
    if (service == null) {
      return R.badRequest("The given path param for service was invalid.");
    }
    IndexProducer indexProducer = indexRebuildService.getIndexProducer(service);

    DataType dataType = EnumUtils.getEnum(DataType.class, dataTypeStr);
    if (dataType == null || !indexProducer.dataTypeSupported(dataType)) {
      return R.badRequest("The given path param for data type was invalid.");
    }

    final SecurityContext securityContext = new SecurityContext(securityService, securityService.getOrganization(),
            securityService.getUser());
    executor.execute(() -> securityContext.runInContext(() -> {
      try {
        logger.info("Starting to repopulate the index from service {}", service);
        indexRebuildService.rebuildIndex(indexProducer, dataType);
      } catch (Throwable t) {
        logger.error("Repopulating the index failed", t);
      }
    }));
    return R.ok();
  }

  @POST
  @Path("rebuild")
  @Operation(
      summary = "Clear and rebuild the index",
      description = "Clear and repopulates the Index directly from the Services"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "OK if repopulation has started")
  })
  public Response rebuildIndex() {
    final SecurityContext securityContext = new SecurityContext(securityService, securityService.getOrganization(),
            securityService.getUser());
    executor.execute(() -> securityContext.runInContext(() -> {
      try {
        logger.info("Starting to repopulate the index");
        indexRebuildService.rebuildIndex(opensearchIndex);
      } catch (Throwable t) {
        logger.error("Repopulating the index failed", t);
      }
    }));
    return R.ok();
  }

  @POST
  @Path("resume/{service}")
  @Operation(
      summary = "Resume rebuilding the index from a service",
      description = "Starts repopulating the Index from a specific service and will then continue with the rest "
          + "of the services that come afterwards"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "OK if repopulation has started")
  })
  public Response resumeIndexRebuild(
      @Parameter(
          description = "The service to start recreating the index "
              + "from. "
              + "The available services are: Series, Scheduler, AssetManager, Comments and Workflow. "
              + "All services that come after the specified service in the order above will also run.",
          required = true
      )
      @PathParam("service") final String serviceStr
  ) {
    Service service = EnumUtils.getEnum(Service.class, serviceStr);
    if (service == null) {
      return R.badRequest("The given path param for service was invalid.");
    }

    final SecurityContext securityContext = new SecurityContext(securityService, securityService.getOrganization(),
            securityService.getUser());
    executor.execute(() -> securityContext.runInContext(() -> {
      try {
        logger.info("Resume repopulating the index from service {}", service);
        indexRebuildService.resumeIndexRebuild(service);
      } catch (Throwable t) {
        logger.error("Repopulating the index failed", t);
      }
    }));
    return R.ok();
  }

  @GET
  @Path("rebuild/states.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the index rebuild states",
      description = "Returns the index rebuild servicerepopulation states"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returns the repopulation states of the index rebuild services")
  })
  public Response getRebuildStates() {
    Map<String, String> states = indexRebuildService.getRebuildStates();
    JsonArray statesAsJson = new JsonArray();
    for (Map.Entry<String, String> entry : states.entrySet()) {
      JsonObject data = new JsonObject();
      data.addProperty("type", entry.getKey());
      data.addProperty("state", entry.getValue());
      data.addProperty("executionOrder", IndexRebuildService.Service.valueOf(entry.getKey()).ordinal());
      statesAsJson.add(data);
    }
    JsonObject service = new JsonObject();
    service.add("service", statesAsJson);
    JsonObject services = new JsonObject();
    services.add("services", service);
    return Response.ok(services.toString()).build();
  }
}
