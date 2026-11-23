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

package org.opencastproject.timelinepreviews.endpoint;

import org.opencastproject.job.api.JaxbJob;
import org.opencastproject.job.api.Job;
import org.opencastproject.job.api.JobProducer;
import org.opencastproject.mediapackage.MediaPackageElement;
import org.opencastproject.mediapackage.MediaPackageElementParser;
import org.opencastproject.mediapackage.Track;
import org.opencastproject.rest.AbstractJobProducerEndpoint;
import org.opencastproject.serviceregistry.api.ServiceRegistry;
import org.opencastproject.timelinepreviews.api.TimelinePreviewsException;
import org.opencastproject.timelinepreviews.api.TimelinePreviewsService;

import org.apache.commons.lang3.StringUtils;
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
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * The REST endpoint for the {@link TimelinePreviewsService} service
 */
@Path("/timelinepreviews")
@Tag(
    name = "Timeline Previews Service REST Endpoint",
    description = "This service generates timeline preview images from media files that contain a video."
)
@Component(
    immediate = true,
    service = TimelinePreviewsRestEndpoint.class,
    property = {
        "service.description=Timeline previews REST Endpoint",
        "opencast.service.type=org.opencastproject.timelinepreviews",
        "opencast.service.path=/timelinepreviews",
        "opencast.service.jobproducer=true"
    }
)
@JaxrsResource
public class TimelinePreviewsRestEndpoint extends AbstractJobProducerEndpoint {

  /** The logger */
  private static final Logger logger = LoggerFactory.getLogger(TimelinePreviewsRestEndpoint.class);

  /** The timeline previews service */
  protected TimelinePreviewsService service;

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
   * Sets the timeline previews service
   *
   * @param timelinePreviewsService
   *          the timeline previews service
   */
  @Reference
  protected void setTimelinePreviewsService(TimelinePreviewsService timelinePreviewsService) {
    this.service = timelinePreviewsService;
  }

  /**
   * Generates timeline preview images for a track.
   *
   * @param trackAsXml
   *          the track xml to create preview images for
   * @return the job in the body of a JAX-RS response
   * @throws Exception
   */
  @POST
  @Path("/create")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Create timeline preview images",
      description = "Create preview images from the given track."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Timeline previews job successfully created"),
      @ApiResponse(responseCode = "400", description = "The track is blank or is not a track."),
      @ApiResponse(responseCode = "500", description = "Internal server error.")
  })
  public Response createTimelinePreviews(
      @Parameter(description = "The track to generate timeline preview images for.", required = true)
      @FormParam("track") String trackAsXml,
      @Parameter(description = "The number of timeline preview images to generate.", required = true)
      @FormParam("imageCount") int imageCount
  ) throws Exception {
    // Ensure that the POST parameters are present
    if (StringUtils.isBlank(trackAsXml)) {
      return Response.status(Response.Status.BAD_REQUEST).entity("track must not be null").build();
    }

    // Deserialize the track
    MediaPackageElement sourceTrack = MediaPackageElementParser.getFromXml(trackAsXml);
    if (!Track.TYPE.equals(sourceTrack.getElementType())) {
      return Response.status(Response.Status.BAD_REQUEST).entity("mediapackage element must be of type track").build();
    }

    try {
      Job job = service.createTimelinePreviewImages((Track) sourceTrack, imageCount);
      return Response.ok().entity(new JaxbJob(job)).build();
    } catch (TimelinePreviewsException e) {
      logger.warn("Generation of timeline preview images failed: " + e.getMessage());
      return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
    }
  }

  @Override
  public JobProducer getService() {
    if (service instanceof JobProducer) {
      return (JobProducer) service;
    } else {
      return null;
    }
  }

  @Override
  public ServiceRegistry getServiceRegistry() {
    return serviceRegistry;
  }

}
