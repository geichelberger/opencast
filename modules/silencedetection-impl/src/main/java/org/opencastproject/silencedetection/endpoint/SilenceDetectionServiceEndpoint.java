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

package org.opencastproject.silencedetection.endpoint;

import org.opencastproject.job.api.JaxbJob;
import org.opencastproject.job.api.Job;
import org.opencastproject.job.api.JobProducer;
import org.opencastproject.mediapackage.MediaPackageElementParser;
import org.opencastproject.mediapackage.Track;
import org.opencastproject.rest.AbstractJobProducerEndpoint;
import org.opencastproject.serviceregistry.api.ServiceRegistry;
import org.opencastproject.silencedetection.api.SilenceDetectionService;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;

import java.util.List;

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
 * SilenceDetectionService REST Endpoint.
 */
@Path("/silencedetection")
@Tag(
    name = "Silence Detection Service REST Endpoint",
    description = "Detect silent sequences in audio file."
)
@Component(
    property = {
        "service.description=Silence Detection Service REST Endpoint",
        "opencast.service.type=org.opencastproject.silencedetection",
        "opencast.service.path=/silencedetection",
        "opencast.service.jobproducer=true"
    },
    immediate = true,
    service = SilenceDetectionServiceEndpoint.class
)
@JaxrsResource
public class SilenceDetectionServiceEndpoint extends AbstractJobProducerEndpoint {

  private SilenceDetectionService silenceDetectionService;
  private ServiceRegistry serviceRegistry;

  @POST
  @Path("/detect")
  @Produces({MediaType.APPLICATION_XML})
  @Operation(
      summary = "Detect silent sequences in a track",
      description = "Create silence detection job."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Silence detection job created successfully."),
      @ApiResponse(responseCode = "500", description = "Create silence detection job failed.")
  })
  public Response detect(
      @Parameter(description = "Track where to run silence detection.", required = true)
      @FormParam("track") String trackXml,
      @Parameter(description = "Tracks referenced by resulting smil (as sources).")
      @FormParam("referenceTracks") String referenceTracksXml
  ) {
    try {
      Track track = (Track) MediaPackageElementParser.getFromXml(trackXml);
      Job job = null;
      if (referenceTracksXml != null) {
        List<Track> referenceTracks = null;
        referenceTracks = (List<Track>) MediaPackageElementParser.getArrayFromXml(referenceTracksXml);
        job = silenceDetectionService.detect(track, referenceTracks.toArray(new Track[referenceTracks.size()]));
      } else {
        job = silenceDetectionService.detect(track);
      }
      return Response.ok(new JaxbJob(job)).build();
    } catch (Exception ex) {
      return Response.serverError().entity(ex.getMessage()).build();
    }
  }

  @Override
  public JobProducer getService() {
    if (silenceDetectionService instanceof JobProducer) {
      return (JobProducer) silenceDetectionService;
    } else {
      return null;
    }
  }

  @Override
  public ServiceRegistry getServiceRegistry() {
    return serviceRegistry;
  }

  @Reference
  public void setSilenceDetectionService(SilenceDetectionService silenceDetectionService) {
    this.silenceDetectionService = silenceDetectionService;
  }

  @Reference
  public void setServiceRegistry(ServiceRegistry serviceRegistry) {
    this.serviceRegistry = serviceRegistry;
  }
}
