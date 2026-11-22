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

package org.opencastproject.publication.youtube.endpoint;

import static org.opencastproject.util.RestUtil.R.badRequest;
import static org.opencastproject.util.RestUtil.R.serverError;

import org.opencastproject.job.api.JaxbJob;
import org.opencastproject.job.api.Job;
import org.opencastproject.job.api.JobProducer;
import org.opencastproject.mediapackage.Attachment;
import org.opencastproject.mediapackage.MediaPackage;
import org.opencastproject.mediapackage.MediaPackageParser;
import org.opencastproject.mediapackage.Track;
import org.opencastproject.publication.api.YouTubePublicationService;
import org.opencastproject.rest.AbstractJobProducerEndpoint;
import org.opencastproject.serviceregistry.api.ServiceRegistry;

import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

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
 * Rest endpoint for publishing media to youtube.
 */
@Path("/youtube")
@Tag(name = "YouTube Publication Service")
@Component(
    immediate = true,
    service = YouTubePublicationRestService.class,
    property = {
        "service.description=YouTube Publication REST Endpoint",
        "opencast.service.type=org.opencastproject.publication.youtube",
        "opencast.service.path=/youtube",
        "opencast.service.jobproducer=true"
    }
)
@JaxrsResource
public class YouTubePublicationRestService extends AbstractJobProducerEndpoint {

  private final Logger logger = LoggerFactory.getLogger(YouTubePublicationRestService.class);

  protected YouTubePublicationService service;

  protected ServiceRegistry serviceRegistry = null;

  @POST
  @Path("/")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Publish a media package element to YouTube",
      description = "Publish a media package element to youtube publication channel"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the publication job"),
      @ApiResponse(responseCode = "400", description = "elementId does not reference a track")
  })
  public Response publish(
      @Parameter(description = "The mediapackage", required = true)
      @FormParam("mediapackage") final String mediaPackageXml,
      @Parameter(description = "The element to publish", required = true)
      @FormParam("elementId") final String elementId,
      @Parameter(description = "The optional thumbnail to publish")
      @FormParam("thumbnailId") final String thumbnailId,
      @Parameter(description = "The captions to publish")
      @FormParam("captionIds") final String captionIds
  ) {
    final Job job;
    try {
      final MediaPackage mediapackage = MediaPackageParser.getFromXml(mediaPackageXml);
      final Track track = mediapackage.getTrack(elementId);
      final Attachment thumbnail = (Attachment) mediapackage.getElementById(thumbnailId);
      if (track != null) {
        final List<Track> captions = new ArrayList<>();
        if (StringUtils.isNotBlank(captionIds)) {
          for (String captionId : StringUtils.split(captionIds, ",")) {
            final Track caption = mediapackage.getTrack(captionId.trim());
            if (caption != null) {
              captions.add(caption);
            }
          }
        }
        job = service.publish(mediapackage, track, thumbnail, captions);
      } else {
        return badRequest();
      }
    } catch (Exception e) {
      logger.warn("Error publishing element '{}' to YouTube", elementId, e);
      return serverError();
    }
    return Response.ok(new JaxbJob(job)).build();
  }

  @POST
  @Path("/retract")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Retract a media package from YouTube",
      description = "Retract a media package from the youtube publication channel"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the retraction job")
  })
  public Response retract(
      @Parameter(description = "The mediapackage", required = true)
      @FormParam("mediapackage") final String mediaPackageXml
  ) {
    final Job job;
    try {
      final MediaPackage mediapackage = MediaPackageParser.getFromXml(mediaPackageXml);
      job = service.retract(mediapackage);
    } catch (Exception e) {
      logger.warn("Unable to retract mediapackage '{}' from YouTube", mediaPackageXml, e);
      return Response.serverError().status(Status.INTERNAL_SERVER_ERROR).build();
    }
    return Response.ok(new JaxbJob(job)).build();
  }

  /**
   * {@inheritDoc}
   *
   * @see org.opencastproject.rest.AbstractJobProducerEndpoint#getService()
   */
  @Override
  public JobProducer getService() {
    return (service instanceof JobProducer) ? (JobProducer) service : null;
  }

  /**
   * Callback from the OSGi declarative services to set the service registry
   *
   * @param serviceRegistry
   *          the service registry
   */
  @Reference
  protected void setServiceRegistry(final ServiceRegistry serviceRegistry) {
    this.serviceRegistry = serviceRegistry;
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
   * Callback from OSGi to set a reference to the youtube publication service.
   *
   * @param service
   *          the service to set
   */
  @Reference
  protected void setService(final YouTubePublicationService service) {
    this.service = service;
  }

}
