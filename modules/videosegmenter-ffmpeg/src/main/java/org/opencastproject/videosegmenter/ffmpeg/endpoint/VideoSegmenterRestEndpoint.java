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

package org.opencastproject.videosegmenter.ffmpeg.endpoint;

import org.opencastproject.job.api.JaxbJob;
import org.opencastproject.job.api.Job;
import org.opencastproject.job.api.JobProducer;
import org.opencastproject.mediapackage.MediaPackageElement;
import org.opencastproject.mediapackage.MediaPackageElementParser;
import org.opencastproject.mediapackage.Track;
import org.opencastproject.rest.AbstractJobProducerEndpoint;
import org.opencastproject.serviceregistry.api.ServiceRegistry;
import org.opencastproject.videosegmenter.api.VideoSegmenterException;
import org.opencastproject.videosegmenter.api.VideoSegmenterService;

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
 * The REST endpoint for the {@link VideoSegmenterService} service
 */
@Path("/analysis/videosegmenter")
@Tag(
    name = "Video Segmentation Service",
    description = "This service performs segmentation of media files."
)
@Component(
    immediate = true,
    service = VideoSegmenterRestEndpoint.class,
    property = {
        "service.description=Video Segmentation REST Endpoint",
        "opencast.service.type=org.opencastproject.videosegmenter",
        "opencast.service.path=/analysis/videosegmenter",
        "opencast.service.jobproducer=true"
    }
)
@JaxrsResource
public class VideoSegmenterRestEndpoint extends AbstractJobProducerEndpoint {

  /** The logger */
  private static final Logger logger = LoggerFactory.getLogger(VideoSegmenterRestEndpoint.class);

  /** The rest docs */
  protected String docs;

  /** The video segmenter */
  protected VideoSegmenterService service;

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
   * Sets the segmenter
   *
   * @param videoSegmenter
   *          the segmenter
   */
  @Reference
  protected void setVideoSegmenter(VideoSegmenterService videoSegmenter) {
    this.service = videoSegmenter;
  }

  /**
   * Segments a track.
   *
   * @param trackAsXml
   *          the track xml to segment
   * @return the job in the body of a JAX-RS response
   * @throws Exception
   */
  @POST
  @Path("")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Segment a video track",
      description = "Submit a track for segmentation."
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "The segmentation job as XML. The job can be polled for the resulting mpeg7 catalog."
      ),
      @ApiResponse(responseCode = "400", description = "The track is blank or is not a track."),
      @ApiResponse(responseCode = "500", description = "The underlying service could not segment the video.")
  })
  public Response segment(
      @Parameter(description = "The track to segment.", required = true)
      @FormParam("track") String trackAsXml
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
      // Asynchronously segment the specified track
      Job job = service.segment((Track) sourceTrack);
      return Response.ok().entity(new JaxbJob(job)).build();
    } catch (VideoSegmenterException e) {
      logger.warn("Segmentation failed: " + e.getMessage());
      return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
    }
  }

  @GET
  @Produces(MediaType.TEXT_HTML)
  @Path("docs")
  @Operation(
      summary = "Get the legacy REST documentation",
      description = "Requests to this path are answered by the REST servlet with a redirect to the legacy REST "
          + "documentation page of the service. Prefer the OpenAPI documentation."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "302", description = "Redirect to the legacy REST documentation.")
  })
  public String getDocs() {
    return docs;
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
