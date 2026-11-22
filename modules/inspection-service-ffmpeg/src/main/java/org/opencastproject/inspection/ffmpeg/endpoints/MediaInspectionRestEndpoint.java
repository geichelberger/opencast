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

package org.opencastproject.inspection.ffmpeg.endpoints;

import org.opencastproject.inspection.api.MediaInspectionService;
import org.opencastproject.inspection.api.util.Options;
import org.opencastproject.job.api.JaxbJob;
import org.opencastproject.job.api.Job;
import org.opencastproject.job.api.JobProducer;
import org.opencastproject.mediapackage.MediaPackageElementParser;
import org.opencastproject.rest.AbstractJobProducerEndpoint;
import org.opencastproject.serviceregistry.api.ServiceRegistry;

import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;

import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * A service endpoint to expose the {@link MediaInspectionService} via REST.
 */
@Path("/inspection")
@Tag(
    name = "Media Inspection Service",
    description = "This service extracts technical metadata from media files."
)
@Component(
    property = {
        "service.description=Media Inspection REST Endpoint",
        "opencast.service.type=org.opencastproject.inspection",
        "opencast.service.path=/inspection",
        "opencast.service.jobproducer=true"
    },
    immediate = true,
    service = { MediaInspectionRestEndpoint.class }
)
@JaxrsResource
public class MediaInspectionRestEndpoint extends AbstractJobProducerEndpoint {

  /** The logger */
  private static final Logger logger = LoggerFactory.getLogger(MediaInspectionRestEndpoint.class);

  /** The inspection service */
  protected MediaInspectionService service;

  /** The service registry */
  protected ServiceRegistry serviceRegistry = null;

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
   * Sets the inspection service
   *
   * @param service
   *          the inspection service
   */
  @Reference(cardinality = ReferenceCardinality.OPTIONAL, policy = ReferencePolicy.DYNAMIC)
  public void setService(MediaInspectionService service) {
    this.service = service;
  }

  /**
   * Removes the inspection service
   *
   * @param service
   */
  public void unsetService(MediaInspectionService service) {
    if (this.service == service) {
      this.service = null;
    }
  }

  /**
   * Callback from OSGi that is called when this service is activated.
   *
   * @param cc
   *          OSGi component context
   */
  @Activate
  public void activate(ComponentContext cc) {
    // String serviceUrl = (String) cc.getProperties().get(RestConstants.SERVICE_PATH_PROPERTY);
  }

  @GET
  @Produces(MediaType.TEXT_XML)
  @Path("inspect")
  @Operation(
      summary = "Inspect a media file",
      description = "Analyze a given media file"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "XML encoded receipt is returned."),
      @ApiResponse(responseCode = "503", description = "Service unavailabe or not currently present"),
      @ApiResponse(responseCode = "500", description = "Problem retrieving media file or invalid media file or URL.")
  })
  public Response inspectTrack(
      @Parameter(description = "Location of the media file.")
      @QueryParam("uri") URI uri,
      @Parameter(description = "Options passed to media inspection service")
      @QueryParam("options") String options
  ) {
    checkNotNull(service);
    try {
      Job job = service.inspect(uri, Options.fromJson(options));
      return Response.ok(new JaxbJob(job)).build();
    } catch (Exception e) {
      logger.info("Unable to inspect track {}: {}", uri, e.getMessage());
      return Response.serverError().build();
    }
  }

  @POST
  @Produces(MediaType.TEXT_XML)
  @Path("enrich")
  @Operation(
      summary = "Enrich a media package element with metadata",
      description = "Analyze and add missing metadata of a given media file"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "XML encoded receipt is returned."),
      @ApiResponse(responseCode = "503", description = "Service unavailabe or not currently present"),
      @ApiResponse(responseCode = "500", description = "Problem retrieving media file or invalid media file or URL.")
  })
  public Response enrichTrack(
      @Parameter(description = "MediaPackage Element, that should be enriched with metadata ", required = true)
      @FormParam("mediaPackageElement") String mediaPackageElement,
      @Parameter(description = "Should the existing metadata values remain", required = true)
      @FormParam("override") boolean override,
      @Parameter(description = "Options passed to media inspection service")
      @FormParam("options") String options
  ) {
    checkNotNull(service);
    try {
      Job job = service.enrich(MediaPackageElementParser.getFromXml(mediaPackageElement), override,
              Options.fromJson(options));
      return Response.ok(new JaxbJob(job)).build();
    } catch (Exception e) {
      logger.info("Unable to enrich track {}: {}", mediaPackageElement, e.getMessage());
      return Response.serverError().build();
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

  /**
   * Checks if the service or services are available, if not it handles it by returning a 503 with a message
   *
   * @param services
   *          an array of services to check
   */
  protected void checkNotNull(Object... services) {
    if (services != null) {
      for (Object object : services) {
        if (object == null) {
          throw new javax.ws.rs.WebApplicationException(javax.ws.rs.core.Response.Status.SERVICE_UNAVAILABLE);
        }
      }
    }
  }

}
