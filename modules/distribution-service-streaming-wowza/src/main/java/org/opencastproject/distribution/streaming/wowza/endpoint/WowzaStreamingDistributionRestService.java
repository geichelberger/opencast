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

package org.opencastproject.distribution.streaming.wowza.endpoint;

import static javax.ws.rs.core.Response.status;

import org.opencastproject.distribution.api.StreamingDistributionService;
import org.opencastproject.job.api.JaxbJob;
import org.opencastproject.job.api.Job;
import org.opencastproject.job.api.JobProducer;
import org.opencastproject.mediapackage.MediaPackage;
import org.opencastproject.mediapackage.MediaPackageElement;
import org.opencastproject.mediapackage.MediaPackageElementParser;
import org.opencastproject.mediapackage.MediaPackageParser;
import org.opencastproject.rest.AbstractJobProducerEndpoint;
import org.opencastproject.serviceregistry.api.ServiceRegistry;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Set;

import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * Rest endpoint for distributing media to the streaming distribution channel.
 */
@Path("/distribution/streaming")
@Tag(
    name = "Streaming Distribution Service",
    description = "This service distributes media packages to the streaming server, especially "
        + "Wowza Streaming Server."
)
@Component(
    immediate = true,
    service = WowzaStreamingDistributionRestService.class,
    property = {
        "service.description=Streaming Distribution REST Endpoint",
        "opencast.service.type=org.opencastproject.distribution.streaming",
        "opencast.service.path=/distribution/streaming",
        "opencast.service.jobproducer=true"
    }
)
@JaxrsResource
public class WowzaStreamingDistributionRestService extends AbstractJobProducerEndpoint {

  /** The logger */
  private static final Logger logger = LoggerFactory.getLogger(WowzaStreamingDistributionRestService.class);

  /** The distribution service */
  private StreamingDistributionService service;

  /** The service registry */
  private ServiceRegistry serviceRegistry = null;

  private static final Gson gson = new Gson();


  /**
   * OSGi activation callback
   *
   * @param cc
   *          this component's context
   */
  @Activate
  public void activate(ComponentContext cc) {
  }

  /**
   * Callback from the OSGi declarative services to set the service registry.
   *
   * @param serviceRegistry
   *          the service registry
   */
  @Reference
  protected void setServiceRegistry(ServiceRegistry serviceRegistry) {
    this.serviceRegistry = serviceRegistry;
  }

  /**
   * @param service
   *          the service to set
   */
  @Reference
  public void setService(StreamingDistributionService service) {
    this.service = service;
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("/publishToStreaming")
  @Operation(
      summary = "Check whether publishing to streaming is configured",
      description = "Checks whether publish to streaming is configured for the current organization"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "Whether publish to streaming is configured for the current organization."
      )
  })
  public Response publishToStreaming() {
    return Response.ok(Boolean.toString(service.publishToStreaming())).build();
  }

  @POST
  @Path("/")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Distribute a media package element to the streaming channel",
      description = "Distribute a media package element to this distribution channel"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the distribution job"),
      @ApiResponse(responseCode = "204", description = "There is no streaming distribution service available"),
      @ApiResponse(
          responseCode = "400",
          description = "The request is invalid, for example because an element does not exist in the media package."
      ),
      @ApiResponse(responseCode = "500", description = "The operation failed or the request cannot be parsed.")
  })
  public Response distribute(
      @Parameter(description = "The mediapackage", required = true)
      @FormParam("mediapackage") String mediaPackageXml,
      @Parameter(description = "The publication channel ID", required = true)
      @FormParam("channelId") String channelId,
      @Parameter(description = "The elements to distribute as Json Array['IdOne','IdTwo']", required = true)
      @FormParam("elementIds") String elementIds
  ) {
    Job job;
    try {
      Set<String> setElementIds = gson.fromJson(elementIds, new TypeToken<Set<String>>() { }.getType());
      MediaPackage mediapackage = MediaPackageParser.getFromXml(mediaPackageXml);
      job = service.distribute(channelId, mediapackage, setElementIds);
      if (job == null) {
        return Response.noContent().build();
      } else {
        return Response.ok(new JaxbJob(job)).build();
      }
    } catch (IllegalArgumentException e) {
      logger.debug("Unable to distribute element", e);
      return status(Status.BAD_REQUEST).build();
    } catch (Exception e) {
      logger.warn("Error distributing element", e);
      return Response.serverError().status(Status.INTERNAL_SERVER_ERROR).build();
    }
  }

  @POST
  @Path("/distributesync")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Distribute a media package element to the streaming channel synchronously",
      description = "Synchronously distribute a media package element to this distribution channel"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the distribution"),
      @ApiResponse(responseCode = "204", description = "There is no streaming distribution service available"),
      @ApiResponse(
          responseCode = "400",
          description = "The request is invalid, for example because an element does not exist in the media package."
      ),
      @ApiResponse(responseCode = "500", description = "The operation failed or the request cannot be parsed.")
  })
  public Response distributeSync(
      @Parameter(description = "The mediapackage", required = true)
      @FormParam("mediapackage") String mediaPackageXml,
      @Parameter(description = "The publication channel ID", required = true)
      @FormParam("channelId") String channelId,
      @Parameter(description = "The elements to distribute as Json Array['IdOne','IdTwo']", required = true)
      @FormParam("elementIds") String elementIds
  ) {
    List<MediaPackageElement> result;
    try {
      Set<String> setElementIds = gson.fromJson(elementIds, new TypeToken<Set<String>>() { }.getType());
      MediaPackage mediapackage = MediaPackageParser.getFromXml(mediaPackageXml);
      result = service.distributeSync(channelId, mediapackage, setElementIds);
      if (result == null || result.isEmpty()) {
        return Response.noContent().build();
      } else {
        return Response.ok(MediaPackageElementParser.getArrayAsXml(result)).build();
      }
    } catch (IllegalArgumentException e) {
      logger.debug("Unable to distribute element", e);
      return status(Status.BAD_REQUEST).build();
    } catch (Exception e) {
      logger.warn("Error distributing element", e);
      return Response.serverError().status(Status.INTERNAL_SERVER_ERROR).build();
    }
  }

  @POST
  @Path("/retract")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Retract a media package element from the streaming channel",
      description = "Retract a media package element from this distribution channel"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the retraction job"),
      @ApiResponse(responseCode = "204", description = "There is no streaming distribution service available"),
      @ApiResponse(
          responseCode = "400",
          description = "The request is invalid, for example because an element does not exist in the media package."
      ),
      @ApiResponse(responseCode = "500", description = "The operation failed or the request cannot be parsed.")
  })
  public Response retract(
      @Parameter(description = "The mediapackage", required = true)
      @FormParam("mediapackage") String mediaPackageXml,
      @Parameter(description = "The publication channel ID", required = true)
      @FormParam("channelId") String channelId,
      @Parameter(description = "The elements to retract as Json Array['IdOne','IdTwo']", required = true)
      @FormParam("elementIds") String elementIds
  ) {
    Job job;
    try {
      Set<String> setElementIds = gson.fromJson(elementIds, new TypeToken<Set<String>>() { }.getType());
      MediaPackage mediapackage = MediaPackageParser.getFromXml(mediaPackageXml);
      job = service.retract(channelId, mediapackage, setElementIds);
      if (job == null) {
        return Response.noContent().build();
      } else {
        return Response.ok(new JaxbJob(job)).build();
      }
    } catch (IllegalArgumentException e) {
      logger.debug("Unable to retract element: {}", e.getMessage());
      return status(Status.BAD_REQUEST).build();
    } catch (Exception e) {
      logger.warn("Unable to retract media package '{}' from streaming channel: {}",
          new Object[] { mediaPackageXml, e });
      return Response.serverError().status(Status.INTERNAL_SERVER_ERROR).build();
    }
  }

  @POST
  @Path("/retractsync")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Retract a media package element from the streaming channel synchronously",
      description = "Synchronously retract a media package element from this distribution channel"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the retraction"),
      @ApiResponse(responseCode = "204", description = "There is no streaming distribution service available"),
      @ApiResponse(
          responseCode = "400",
          description = "The request is invalid, for example because an element does not exist in the media package."
      ),
      @ApiResponse(responseCode = "500", description = "The operation failed or the request cannot be parsed.")
  })
  public Response retractSync(
      @Parameter(description = "The mediapackage", required = true)
      @FormParam("mediapackage") String mediaPackageXml,
      @Parameter(description = "The publication channel ID", required = true)
      @FormParam("channelId") String channelId,
      @Parameter(description = "The elements to retract as Json Array['IdOne','IdTwo']", required = true)
      @FormParam("elementIds") String elementIds
  ) {
    List<MediaPackageElement> result;
    try {
      Set<String> setElementIds = gson.fromJson(elementIds, new TypeToken<Set<String>>() { }.getType());
      MediaPackage mediapackage = MediaPackageParser.getFromXml(mediaPackageXml);
      result = service.retractSync(channelId, mediapackage, setElementIds);
      if (result == null || result.isEmpty()) {
        return Response.noContent().build();
      } else {
        return Response.ok(MediaPackageElementParser.getArrayAsXml(result)).build();
      }
    } catch (IllegalArgumentException e) {
      logger.debug("Unable to retract element", e);
      return status(Status.BAD_REQUEST).build();
    } catch (Exception e) {
      logger.warn("Unable to retract mediapackage '{}' from streaming channel: {}",
          new Object[] { mediaPackageXml, e });
      return Response.serverError().status(Status.INTERNAL_SERVER_ERROR).build();
    }
  }

  /**
   * {@inheritDoc}
   *
   * @see org.opencastproject.rest.AbstractJobProducerEndpoint#getService()
   */
  @Override
  public JobProducer getService() {
    if (service instanceof JobProducer) {
      return (JobProducer) service;
    } else {
      return null;
    }
  }

  /**
   * {@inheritDoc}
   *
   * @see org.opencastproject.rest.AbstractJobProducerEndpoint#getServiceRegistry()
   */
  @Override
  public ServiceRegistry getServiceRegistry() {
    return serviceRegistry;
  }

}
