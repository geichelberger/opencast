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
package org.opencastproject.waveform.endpoint;

import org.opencastproject.job.api.JaxbJob;
import org.opencastproject.job.api.Job;
import org.opencastproject.job.api.JobProducer;
import org.opencastproject.mediapackage.MediaPackageElement;
import org.opencastproject.mediapackage.MediaPackageElementParser;
import org.opencastproject.mediapackage.MediaPackageException;
import org.opencastproject.mediapackage.Track;
import org.opencastproject.rest.AbstractJobProducerEndpoint;
import org.opencastproject.serviceregistry.api.ServiceRegistry;
import org.opencastproject.waveform.api.WaveformService;
import org.opencastproject.waveform.api.WaveformServiceException;

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

@Path("/waveform")
@Tag(
    name = "Waveform Service REST Endpoint",
    description = "The Waveform Service generates a waveform image from a media file with at least one audio channel."
)
@Component(
    immediate = true,
    service = WaveformServiceEndpoint.class,
    property = {
        "service.description=Waveform Service REST Endpoint",
        "opencast.service.type=org.opencastproject.waveform",
        "opencast.service.path=/waveform",
        "opencast.service.jobproducer=true"
    }
)
@JaxrsResource
public class WaveformServiceEndpoint extends AbstractJobProducerEndpoint {
  private static final Logger logger = LoggerFactory.getLogger(WaveformServiceEndpoint.class);

  private ServiceRegistry serviceRegistry = null;
  private WaveformService waveformService = null;

  @POST
  @Path("/create")
  @Produces({MediaType.APPLICATION_XML})
  @Operation(
      summary = "Create a waveform image",
      description = "Create a waveform image from the given track"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Waveform generation job successfully created."),
      @ApiResponse(responseCode = "400", description = "The given track can't be parsed."),
      @ApiResponse(responseCode = "500", description = "Internal server error.")
  })
  public Response createWaveformImage(
      @Parameter(description = "Track with at least one audio channel.", required = true)
      @FormParam("track") String track,
      @Parameter(description = "Width of waveform image in pixels per minute.", required = true)
      @FormParam("pixelsPerMinute") int pixelsPerMinute,
      @Parameter(description = "Minimum width of waveform image.", required = true)
      @FormParam("minWidth") int minWidth,
      @Parameter(description = "Maximum width of waveform image.", required = true)
      @FormParam("maxWidth") int maxWidth,
      @Parameter(description = "Height of waveform image.", required = true)
      @FormParam("height") int height,
      @Parameter(description = "Color of waveform image.", required = true, schema = @Schema(example = "black"))
      @FormParam("color") String color
  ) {
    try {
      MediaPackageElement sourceTrack = MediaPackageElementParser.getFromXml(track);
      if (!Track.TYPE.equals(sourceTrack.getElementType())) {
        return Response.status(Response.Status.BAD_REQUEST).entity("Track element must be of type track").build();
      }

      Job job = waveformService.createWaveformImage(
          (Track) sourceTrack, pixelsPerMinute, minWidth, maxWidth, height, color);
      return Response.ok().entity(new JaxbJob(job)).build();
    } catch (WaveformServiceException ex) {
      logger.error("Creating waveform job for track {} failed:", track, ex);
      return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
    } catch (MediaPackageException ex) {
      return Response.status(Response.Status.BAD_REQUEST).entity("Track element parsing failure").build();
    }
  }

  @Override
  public JobProducer getService() {
    if (waveformService instanceof JobProducer) {
      return (JobProducer) waveformService;
    } else {
      return null;
    }
  }

  @Override
  public ServiceRegistry getServiceRegistry() {
    return serviceRegistry;
  }

  @Reference
  public void setServiceRegistry(ServiceRegistry serviceRegistry) {
    this.serviceRegistry = serviceRegistry;
  }

  @Reference
  public void setWaveformService(WaveformService waveformService) {
    this.waveformService = waveformService;
  }
}
