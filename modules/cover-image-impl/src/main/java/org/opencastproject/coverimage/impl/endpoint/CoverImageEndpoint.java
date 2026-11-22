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

package org.opencastproject.coverimage.impl.endpoint;

import org.opencastproject.coverimage.CoverImageException;
import org.opencastproject.coverimage.CoverImageService;
import org.opencastproject.job.api.JaxbJob;
import org.opencastproject.job.api.Job;
import org.opencastproject.job.api.JobProducer;
import org.opencastproject.rest.AbstractJobProducerEndpoint;
import org.opencastproject.serviceregistry.api.ServiceRegistry;

import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * REST endpoint for {@link CoverImageService}
 */
@Path("/cover-image")
@Tag(
    name = "Cover Image Service",
    description = "This endpoint triggers generation of cover images"
)
@Component(
    immediate = true,
    service = CoverImageEndpoint.class,
    property = {
        "service.description=Cover Image Service REST Endpoint",
        "opencast.service.type=org.opencastproject.coverimage",
        "opencast.service.path=/cover-image",
        "opencast.service.jobproducer=true"
    }
)
@JaxrsResource
public class CoverImageEndpoint extends AbstractJobProducerEndpoint {

  /** Reference to the service registry service */
  private ServiceRegistry serviceRegistry;

  /** Reference to the cover image service */
  private CoverImageService coverImageService;

  /** The logging facility */
  private static final Logger logger = LoggerFactory.getLogger(CoverImageEndpoint.class);

  @Override
  public JobProducer getService() {
    if (coverImageService instanceof JobProducer) {
      return (JobProducer) coverImageService;
    } else {
      return null;
    }
  }

  @Override
  public ServiceRegistry getServiceRegistry() {
    return serviceRegistry;
  }

  @POST
  @Path("generate")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Generate a cover image",
      description = "Generates a cover image based on the given metadata"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "Results in an xml document containing the job for the cover image generation task"
      ),
      @ApiResponse(responseCode = "500", description = "The cover image job could not be created.")
  })
  public Response generateCoverImage(
      @Parameter(description = "Metadata XML")
      @FormParam("xml") String xml,
      @Parameter(description = "XSLT stylesheet", required = true)
      @FormParam("xsl") String xsl,
      @Parameter(description = "Width of the cover image", required = true, schema = @Schema(example = "1600"))
      @FormParam("width") String width,
      @Parameter(description = "Height of the cover image", required = true, schema = @Schema(example = "900"))
      @FormParam("height") String height,
      @Parameter(description = "URI of poster image")
      @FormParam("posterimage") String posterFlavor,
      @Parameter(
          description = "Flavor of target cover image",
          required = true,
          schema = @Schema(example = "image/cover")
      )
      @FormParam("targetflavor") String targetFlavor
  ) {
    try {
      Job job = coverImageService.generateCoverImage(xml, xsl, width, height, posterFlavor, targetFlavor);
      return Response.ok().entity(new JaxbJob(job)).build();
    } catch (CoverImageException e) {
      logger.warn("Error while creating cover image job via REST endpoint: {}", e.getMessage());
      return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
    }
  }

  /**
   * OSGi callback to set the a reference to the service registry.
   *
   * @param serviceRegistry
   *          the service registry
   */
  @Reference
  protected void setServiceRegistry(ServiceRegistry serviceRegistry) {
    this.serviceRegistry = serviceRegistry;
  }

  /**
   * OSGi callback to set the a reference to the cover image service.
   *
   * @param coverImageService
   */
  @Reference
  protected void setCoverImageService(CoverImageService coverImageService) {
    this.coverImageService = coverImageService;
  }

  /**
   * Callback from OSGi that is called when this service is activated.
   *
   * @param cc
   *          OSGi component context
   */
  @Activate
  protected void activate(ComponentContext cc) {
    logger.info("Cover Image REST Endpoint started");
  }

}
