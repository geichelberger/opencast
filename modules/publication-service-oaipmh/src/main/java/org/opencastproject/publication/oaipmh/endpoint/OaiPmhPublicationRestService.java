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
package org.opencastproject.publication.oaipmh.endpoint;

import static org.opencastproject.publication.api.OaiPmhPublicationService.SEPARATOR;

import org.opencastproject.job.api.JaxbJob;
import org.opencastproject.job.api.Job;
import org.opencastproject.job.api.JobProducer;
import org.opencastproject.mediapackage.MediaPackage;
import org.opencastproject.mediapackage.MediaPackageElement;
import org.opencastproject.mediapackage.MediaPackageElementFlavor;
import org.opencastproject.mediapackage.MediaPackageElementParser;
import org.opencastproject.mediapackage.MediaPackageException;
import org.opencastproject.mediapackage.MediaPackageParser;
import org.opencastproject.mediapackage.Publication;
import org.opencastproject.publication.api.OaiPmhPublicationService;
import org.opencastproject.rest.AbstractJobProducerEndpoint;
import org.opencastproject.serviceregistry.api.ServiceRegistry;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

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
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * Rest endpoint for publishing media to the OAI-PMH publication channel.
 */
@Path("/publication/oaipmh")
@Tag(
    name = "OAI-PMH Publication Service",
    description = "This service publishes a media package element to the Opencast OAI-PMH channel."
)
@Component(
    immediate = true,
    service = OaiPmhPublicationRestService.class,
    property = {
        "service.description=OAI-PMH Publication REST Endpoint",
        "opencast.service.type=org.opencastproject.publication.oaipmh",
        "opencast.service.path=/publication/oaipmh",
        "opencast.service.jobproducer=true"
    }
)
@JaxrsResource
public class OaiPmhPublicationRestService extends AbstractJobProducerEndpoint {

  /** The logger */
  private static final Logger logger = LoggerFactory.getLogger(OaiPmhPublicationRestService.class);
  private static final Pattern SEPARATE_PATTERN = Pattern.compile(SEPARATOR);

  /** The OAI-PMH publication service */
  protected OaiPmhPublicationService service;

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
   * @param service
   *          the service to set
   */
  @Reference
  public void setService(OaiPmhPublicationService service) {
    this.service = service;
  }

  private static Set<String> split(final String s) {
    if (s == null) {
      return java.util.Collections.emptySet();
    }
    return SEPARATE_PATTERN.splitAsStream(s).collect(Collectors.toSet());
  }

  @POST
  @Path("/")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Publish a media package to an OAI-PMH channel",
      description = "Publish a media package element to this publication channel"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the publication job"),
      @ApiResponse(
          responseCode = "400",
          description = "The request is invalid, for example because a given element does not exist in the "
              + "media package."
      ),
      @ApiResponse(responseCode = "500", description = "The operation failed or the request cannot be parsed.")
  })
  public Response publish(
      @Parameter(description = "The media package", required = true)
      @FormParam("mediapackage") String mediaPackageXml,
      @Parameter(description = "The channel name", required = true)
      @FormParam("channel") String channel,
      @Parameter(
          description = "The elements to publish to download separated by '" + SEPARATOR + "'",
          required = true
      )
      @FormParam("downloadElementIds") String downloadElementIds,
      @Parameter(
          description = "The elements to publish to streaming separated by '" + SEPARATOR + "'",
          required = true
      )
      @FormParam("streamingElementIds") String streamingElementIds,
      @Parameter(description = "Whether to check for availability", schema = @Schema(example = "true"))
      @FormParam("checkAvailability") @DefaultValue("true") boolean checkAvailability
  ) throws Exception {
    final Job job;
    try {
      final MediaPackage mediaPackage = MediaPackageParser.getFromXml(mediaPackageXml);
      job = service.publish(mediaPackage, channel, split(downloadElementIds),
          split(streamingElementIds), checkAvailability);
    } catch (IllegalArgumentException e) {
      logger.warn("Unable to create an publication job", e);
      return Response.status(Status.BAD_REQUEST).build();
    } catch (Exception e) {
      logger.warn("Error publishing element", e);
      return Response.serverError().build();
    }
    return Response.ok(new JaxbJob(job)).build();
  }

  @POST
  @Path("/replace")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Replace a media package in an OAI-PMH channel",
      description = "Replace a media package in this publication channel"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the publication job"),
      @ApiResponse(
          responseCode = "400",
          description = "The request is invalid, for example because a given element does not exist in the "
              + "media package."
      ),
      @ApiResponse(responseCode = "500", description = "The operation failed or the request cannot be parsed.")
  })
  public Response replace(
      @Parameter(description = "The media package", required = true)
      @FormParam("mediapackage") final String mediaPackageXml,
      @Parameter(description = "The channel name", required = true)
      @FormParam("channel") final String channel,
      @Parameter(description = "The additional elements to publish to download", required = true)
      @FormParam("downloadElements") final String downloadElementsXml,
      @Parameter(description = "The additional elements to publish to streaming", required = true)
      @FormParam("streamingElements") final String streamingElementsXml,
      @Parameter(
          description = "The flavors of the elements to retract from download separated by  '" + SEPARATOR + "'",
          required = true
      )
      @FormParam("retractDownloadFlavors") final String retractDownloadFlavorsString,
      @Parameter(
          description = "The flavors of the elements to retract from streaming separated by  '" + SEPARATOR + "'",
          required = true
      )
      @FormParam("retractStreamingFlavors") final String retractStreamingFlavorsString,
      @Parameter(description = "The publications to update", required = true)
      @FormParam("publications") final String publicationsXml,
      @Parameter(description = "Whether to check for availability", schema = @Schema(example = "true"))
      @FormParam("checkAvailability") @DefaultValue("true") final boolean checkAvailability
  ) {
    final Job job;
    try {
      final MediaPackage mediaPackage = MediaPackageParser.getFromXml(mediaPackageXml);
      final Set<? extends MediaPackageElement> downloadElements = new HashSet<MediaPackageElement>(
              MediaPackageElementParser.getArrayFromXml(downloadElementsXml));
      final Set<? extends MediaPackageElement> streamingElements = new HashSet<MediaPackageElement>(
              MediaPackageElementParser.getArrayFromXml(streamingElementsXml));
      final Set<MediaPackageElementFlavor> retractDownloadFlavors = split(retractDownloadFlavorsString).stream()
          .filter(s -> !s.isEmpty())
          .map(MediaPackageElementFlavor::parseFlavor)
          .collect(Collectors.toSet());
      final Set<MediaPackageElementFlavor> retractStreamingFlavors = split(retractStreamingFlavorsString).stream()
          .filter(s -> !s.isEmpty())
          .map(MediaPackageElementFlavor::parseFlavor)
          .collect(Collectors.toSet());
      final Set<? extends Publication> publications = MediaPackageElementParser.getArrayFromXml(publicationsXml)
          .stream().map(p -> (Publication) p).collect(Collectors.toSet());
      job = service.replace(mediaPackage, channel, downloadElements, streamingElements, retractDownloadFlavors,
          retractStreamingFlavors, publications, checkAvailability);
    } catch (IllegalArgumentException e) {
      logger.warn("Unable to create a publication job", e);
      return Response.status(Status.BAD_REQUEST).build();
    } catch (Exception e) {
      logger.warn("Error publishing or retracting element", e);
      return Response.serverError().build();
    }
    return Response.ok(new JaxbJob(job)).build();
  }

  @POST
  @Path("/replacesync")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Replace a media package in an OAI-PMH channel synchronously",
      description = "Synchronously Replace a media package in this publication channel"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the publication"),
      @ApiResponse(responseCode = "500", description = "The operation failed or the request cannot be parsed.")
  })
  public Response replaceSync(
      @Parameter(description = "The media package", required = true)
      @FormParam("mediapackage") final String mediaPackageXml,
      @Parameter(description = "The channel name", required = true)
      @FormParam("channel") final String channel,
      @Parameter(description = "The additional elements to publish to download", required = true)
      @FormParam("downloadElements") final String downloadElementsXml,
      @Parameter(description = "The additional elements to publish to streaming", required = true)
      @FormParam("streamingElements") final String streamingElementsXml,
      @Parameter(
          description = "The flavors of the elements to retract from download separated by  '" + SEPARATOR + "'",
          required = true
      )
      @FormParam("retractDownloadFlavors") final String retractDownloadFlavorsString,
      @Parameter(
          description = "The flavors of the elements to retract from streaming separated by  '" + SEPARATOR + "'",
          required = true
      )
      @FormParam("retractStreamingFlavors") final String retractStreamingFlavorsString,
      @Parameter(description = "The publications to update", required = true)
      @FormParam("publications") final String publicationsXml,
      @Parameter(description = "Whether to check for availability", schema = @Schema(example = "true"))
      @FormParam("checkAvailability") @DefaultValue("true") final boolean checkAvailability
  ) throws MediaPackageException {
    final Publication publication;
    try {
      final MediaPackage mediaPackage = MediaPackageParser.getFromXml(mediaPackageXml);
      final Set<? extends MediaPackageElement> downloadElements = new HashSet<MediaPackageElement>(
          MediaPackageElementParser.getArrayFromXml(downloadElementsXml));
      final Set<? extends MediaPackageElement> streamingElements = new HashSet<MediaPackageElement>(
          MediaPackageElementParser.getArrayFromXml(streamingElementsXml));
      final Set<MediaPackageElementFlavor> retractDownloadFlavors = split(retractDownloadFlavorsString).stream()
          .filter(s -> !s.isEmpty())
          .map(MediaPackageElementFlavor::parseFlavor)
          .collect(Collectors.toSet());
      final Set<MediaPackageElementFlavor> retractStreamingFlavors = split(retractStreamingFlavorsString).stream()
          .filter(s -> !s.isEmpty())
          .map(MediaPackageElementFlavor::parseFlavor)
          .collect(Collectors.toSet());
      final Set<? extends Publication> publications = MediaPackageElementParser.getArrayFromXml(publicationsXml)
          .stream().map(p -> (Publication) p).collect(Collectors.toSet());
      publication = service.replaceSync(mediaPackage, channel, downloadElements, streamingElements,
          retractDownloadFlavors, retractStreamingFlavors, publications, checkAvailability);
    } catch (Exception e) {
      logger.warn("Error publishing or retracting element", e);
      return Response.serverError().build();
    }
    return Response.ok(MediaPackageElementParser.getAsXml(publication)).build();
  }

  @POST
  @Path("/retract")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Retract a media package from an OAI-PMH channel",
      description = "Retract a media package element from this publication channel"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the retraction job"),
      @ApiResponse(responseCode = "400", description = "The request is invalid."),
      @ApiResponse(responseCode = "500", description = "The operation failed or the request cannot be parsed.")
  })
  public Response retract(
      @Parameter(description = "The media package", required = true)
      @FormParam("mediapackage") String mediaPackageXml,
      @Parameter(description = "The OAI-PMH channel to retract from", required = true)
      @FormParam("channel") String channel
  ) throws Exception {
    Job job = null;
    MediaPackage mediaPackage = null;
    try {
      mediaPackage = MediaPackageParser.getFromXml(mediaPackageXml);
      job = service.retract(mediaPackage, channel);
    } catch (IllegalArgumentException e) {
      logger.debug("Unable to create an retract job", e);
      return Response.status(Status.BAD_REQUEST).build();
    } catch (Exception e) {
      logger.warn("Unable to retract media package '{}' from the OAI-PMH channel {}",
              mediaPackage != null ? mediaPackage.getIdentifier().toString() : "<parsing error>", channel, e);
      return Response.serverError().build();
    }
    return Response.ok(new JaxbJob(job)).build();
  }

  @POST
  @Path("/updateMetadata")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Update the metadata of a published media package",
      description = "Update metadata of an published media package. "
          + "This endpoint does not update any media files. If you want to update the whole media package, use the "
          + "publish endpoint."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the publication job"),
      @ApiResponse(
          responseCode = "400",
          description = "The request is invalid, for example because a given element does not exist in the "
              + "media package."
      ),
      @ApiResponse(responseCode = "500", description = "The operation failed or the request cannot be parsed.")
  })
  public Response updateMetadata(
      @Parameter(description = "The updated media package", required = true)
      @FormParam("mediapackage") String mediaPackageXml,
      @Parameter(description = "The channel name", required = true)
      @FormParam("channel") String channel,
      @Parameter(
          description = "The element flavors to be updated, separated by '" + SEPARATOR + "'",
          required = true
      )
      @FormParam("flavors") String flavors,
      @Parameter(
          description = "The element tags to be updated, separated by '" + SEPARATOR + "'",
          required = true
      )
      @FormParam("tags") String tags,
      @Parameter(description = "Whether to check for availability", schema = @Schema(example = "true"))
      @FormParam("checkAvailability") @DefaultValue("true") boolean checkAvailability
  ) throws Exception {
    final Job job;
    try {
      final MediaPackage mediaPackage = MediaPackageParser.getFromXml(mediaPackageXml);
      job = service.updateMetadata(mediaPackage, channel, split(flavors), split(tags), checkAvailability);
    } catch (IllegalArgumentException e) {
      logger.debug("Unable to create an update metadata job", e);
      return Response.status(Status.BAD_REQUEST).build();
    } catch (Exception e) {
      logger.warn("Error publishing element", e);
      return Response.serverError().build();
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
    if (service instanceof JobProducer) {
      return (JobProducer) service;
    } else {
      return null;
    }
  }

  /**
   * {@inheritDoc}
   *
   * @see org.opencastproject.job.api.AbstractJobProducer#getServiceRegistry()
   */
  @Override
  public ServiceRegistry getServiceRegistry() {
    return serviceRegistry;
  }

}
