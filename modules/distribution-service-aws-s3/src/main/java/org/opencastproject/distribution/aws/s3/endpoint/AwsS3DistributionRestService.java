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
package org.opencastproject.distribution.aws.s3.endpoint;

import static javax.ws.rs.core.Response.status;

import org.opencastproject.distribution.aws.s3.api.AwsS3DistributionService;
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

import javax.ws.rs.DefaultValue;
import javax.ws.rs.FormParam;
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
 * Rest endpoint for distributing files to AWS S3.
 */
@Path("/distribution/s3")
@Tag(
    name = "AWS S3 Distribution Service",
    description = "This service distributes media package elements to AWS S3."
)
@Component(
    immediate = true,
    service = AwsS3DistributionRestService.class,
    property = {
        "service.description=AWS S3 Distribution REST Endpoint",
        "opencast.service.type=org.opencastproject.distribution.aws.s3",
        "opencast.service.path=/distribution/s3",
        "opencast.service.jobproducer=true"
    }
)
@JaxrsResource
public class AwsS3DistributionRestService extends AbstractJobProducerEndpoint {

  /** The logger */
  private static final Logger logger = LoggerFactory.getLogger(AwsS3DistributionRestService.class);

  /** The distribution service */
  protected AwsS3DistributionService service;

  /** The service registry */
  protected ServiceRegistry serviceRegistry = null;

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
  @Reference(target = "(distribution.channel=aws.s3)")
  public void setService(AwsS3DistributionService service) {
    this.service = service;
  }

  @POST
  @Path("/")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Distribute a media package element",
      description = "Distribute a media package element to this distribution channel"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the distribution job"),
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
      @Parameter(
          description = "The element to distribute. The Id or multiple Ids as JSON Array ( ['IdOne','IdTwo'] )",
          required = true
      )
      @FormParam("elementId") String elementId,
      @Parameter(description = "If the service should try to access the distributed element")
      @FormParam("checkAvailability") @DefaultValue("true") boolean checkAvailability
  ) throws Exception {
    Job job = null;
    try {
      Gson gson = new Gson();
      Set<String> setElementIds = gson.fromJson(elementId, new TypeToken<Set<String>>() { }.getType());
      MediaPackage mediapackage = MediaPackageParser.getFromXml(mediaPackageXml);
      job = service.distribute(channelId, mediapackage, setElementIds, checkAvailability);
    } catch (IllegalArgumentException e) {
      logger.debug("Unable to distribute element: {}", e.getMessage());
      return status(Status.BAD_REQUEST).build();
    } catch (Exception e) {
      logger.warn("Unable to distribute media package {}, element {} to aws s3 channel",
          mediaPackageXml, elementId, e);
      return Response.serverError().status(Status.INTERNAL_SERVER_ERROR).build();
    }
    return Response.ok(new JaxbJob(job)).build();
  }

  @POST
  @Path("/distributesync")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Distribute a media package element synchronously",
      description = "Synchronously distribute a media package element to this distribution channel"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the distribution"),
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
      @Parameter(
          description = "The element to distribute. The Id or multiple Ids as JSON Array ( ['IdOne','IdTwo'] )",
          required = true
      )
      @FormParam("elementId") String elementId,
      @Parameter(description = "If the service should try to access the distributed element")
      @FormParam("checkAvailability") @DefaultValue("true") boolean checkAvailability
  ) throws Exception {
    List<MediaPackageElement> result = null;
    try {
      Gson gson = new Gson();
      Set<String> setElementIds = gson.fromJson(elementId, new TypeToken<Set<String>>() { }.getType());
      MediaPackage mediapackage = MediaPackageParser.getFromXml(mediaPackageXml);
      result = service.distributeSync(channelId, mediapackage, setElementIds, checkAvailability);
    } catch (IllegalArgumentException e) {
      logger.debug("Unable to distribute element: {}", e.getMessage());
      return status(Status.BAD_REQUEST).build();
    } catch (Exception e) {
      logger.warn("Unable to distribute media package {}, element {} to aws s3 channel",
          mediaPackageXml, elementId, e);
      return Response.serverError().status(Status.INTERNAL_SERVER_ERROR).build();
    }
    return Response.ok(MediaPackageElementParser.getArrayAsXml(result)).build();
  }

  @POST
  @Path("/retract")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Retract a media package element",
      description = "Retract a media package element from this distribution channel"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the retraction job"),
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
      @Parameter(
          description = "The element to retract. The Id or multiple Ids as JSON Array ( ['IdOne','IdTwo'] )",
          required = true
      )
      @FormParam("elementId") String elementId
  ) throws Exception {
    Job job = null;
    try {
      Gson gson = new Gson();
      Set<String> setElementIds = gson.fromJson(elementId, new TypeToken<Set<String>>() { }.getType());
      MediaPackage mediapackage = MediaPackageParser.getFromXml(mediaPackageXml);
      job = service.retract(channelId, mediapackage, setElementIds);
    } catch (IllegalArgumentException e) {
      logger.debug("Unable to retract element: {}", e.getMessage());
      return status(Status.BAD_REQUEST).build();
    } catch (Exception e) {
      logger.warn("Unable to retract media package {}, element {} from aws s3 channel",
          mediaPackageXml, elementId, e);
      return Response.serverError().status(Status.INTERNAL_SERVER_ERROR).build();
    }
    return Response.ok(new JaxbJob(job)).build();
  }

  @POST
  @Path("/retractsync")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Retract a media package element synchronously",
      description = "Synchronously retract a media package element from this distribution channel"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the retraction"),
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
      @Parameter(
          description = "The element to retract. The Id or multiple Ids as JSON Array ( ['IdOne','IdTwo'] )",
          required = true
      )
      @FormParam("elementId") String elementId
  ) throws Exception {
    List<MediaPackageElement> result = null;
    try {
      Gson gson = new Gson();
      Set<String> setElementIds = gson.fromJson(elementId, new TypeToken<Set<String>>() { }.getType());
      MediaPackage mediapackage = MediaPackageParser.getFromXml(mediaPackageXml);
      result = service.retractSync(channelId, mediapackage, setElementIds);
    } catch (IllegalArgumentException e) {
      logger.debug("Unable to retract element: {}", e.getMessage());
      return status(Status.BAD_REQUEST).build();
    } catch (Exception e) {
      logger.warn("Unable to retract media package {}, element {} from aws s3 channel",
          mediaPackageXml, elementId, e);
      return Response.serverError().status(Status.INTERNAL_SERVER_ERROR).build();
    }
    return Response.ok(MediaPackageElementParser.getArrayAsXml(result)).build();
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
