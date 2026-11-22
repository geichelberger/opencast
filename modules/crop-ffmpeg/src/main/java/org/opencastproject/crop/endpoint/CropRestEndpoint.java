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

package org.opencastproject.crop.endpoint;

import org.opencastproject.crop.api.CropException;
import org.opencastproject.crop.api.CropService;
import org.opencastproject.job.api.JaxbJob;
import org.opencastproject.job.api.Job;
import org.opencastproject.job.api.JobProducer;
import org.opencastproject.mediapackage.MediaPackageElement;
import org.opencastproject.mediapackage.MediaPackageElementParser;
import org.opencastproject.mediapackage.Track;
import org.opencastproject.rest.AbstractJobProducerEndpoint;
import org.opencastproject.serviceregistry.api.ServiceRegistry;

import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
 * The REST endpoint for the {@link CropService} service.
 */
@Path("/crop")
@Tag(
    name = "Video CROP Service",
    description = "This service is not ready"
)
@Component(
    immediate = true,
    service = CropRestEndpoint.class,
    property = {
        "service.description=Video Crop REST Endpoint",
        "opencast.service.type=org.opencastproject.crop",
        "opencast.service.path=/crop",
        "opencast.service.jobproducer=true"
    }
)
@JaxrsResource
public class CropRestEndpoint extends AbstractJobProducerEndpoint {
  /**
   * The logger
   */
  private static final Logger logger = LoggerFactory.getLogger(CropRestEndpoint.class);

  /**
   * The rest docs
   */
  protected String docs;

  /**
   * The cropper
   */
  protected CropService cropService;

  /**
   * The service registry
   */
  protected ServiceRegistry serviceRegistry = null;

  /**
   * Callback from OSGi declarative services to set the service registry.
   *
   * @param serviceRegistry the service registry
   */
  @Reference
  protected void setServiceRegistry(ServiceRegistry serviceRegistry) {
    this.serviceRegistry = serviceRegistry;
  }

  /**
   * Sets the cropper.
   *
   * @param cropService the cropper
   */
  @Reference
  protected void setCropService(CropService cropService) {
    this.cropService = cropService;
  }

  @POST
  @Path("")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Crop a track",
      description = "Submit a track for cropping"
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "The job ID to use when polling for the resulting mpeg7 catalog."
      ),
      @ApiResponse(responseCode = "400", description = "The \"crop\" is NULL or not a valid track type."),
      @ApiResponse(responseCode = "500", description = "The underlying service could not crop the video.")
  })
  public Response crop(
      @Parameter(description = "The track to crop.", required = true)
      @FormParam("track") String trackAsXml
  ) throws Exception {
    if (StringUtils.isBlank(trackAsXml)) {
      return Response.status(Response.Status.BAD_REQUEST)
          .entity("track must not be null")
          .build();
    }

    MediaPackageElement sourceTrack = MediaPackageElementParser.getFromXml(trackAsXml);
    if (!Track.TYPE.equals(sourceTrack.getElementType())) {
      return Response.status(Response.Status.BAD_REQUEST)
          .entity("mediapackage element must be of type track")
          .build();
    }

    try {
      Job job = cropService.crop((Track) sourceTrack);
      return Response.ok().entity(new JaxbJob(job)).build();
    } catch (CropException e) {
      logger.warn("cropping failed: :" + e.getMessage());
      return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
    }
  }

  @GET
  @Produces(MediaType.TEXT_HTML)
  @Path("docs")
  public String getDocs() {
    return docs;
  }

  /**
   * {@inheritDoc}
   *
   * @see AbstractJobProducerEndpoint#getService()
   */
  @Override
  public JobProducer getService() {
    if (cropService instanceof JobProducer) {
      return (JobProducer) cropService;
    } else {
      return null;
    }
  }

  /**
   * {@inheritDoc}
   *
   * @see AbstractJobProducerEndpoint#getServiceRegistry()
   */
  @Override
  public ServiceRegistry getServiceRegistry() {
    return serviceRegistry;
  }
}
