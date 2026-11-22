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
package org.opencastproject.publication.configurable.endpoint;

import org.opencastproject.job.api.JaxbJob;
import org.opencastproject.job.api.Job;
import org.opencastproject.job.api.JobProducer;
import org.opencastproject.mediapackage.MediaPackage;
import org.opencastproject.mediapackage.MediaPackageElement;
import org.opencastproject.mediapackage.MediaPackageElementParser;
import org.opencastproject.mediapackage.MediaPackageParser;
import org.opencastproject.mediapackage.Publication;
import org.opencastproject.publication.api.ConfigurablePublicationService;
import org.opencastproject.rest.AbstractJobProducerEndpoint;
import org.opencastproject.serviceregistry.api.ServiceRegistry;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

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
 * Rest endpoint, mainly for publishing media to a configurable channel
 */
@Path("/publication/api")
@Tag(
    name = "Configurable Publication Service",
    description = "This service publishes and retracts media package elements to a configurable channel"
)
@Component(
    immediate = true,
    service = ConfigurablePublicationRestService.class,
    property = {
        "service.description=Configurable Publication REST Endpoint",
        "opencast.service.type=org.opencastproject.publication.configurable",
        "opencast.service.path=/publication/api",
        "opencast.service.jobproducer=true"
    }
)
@JaxrsResource
public class ConfigurablePublicationRestService extends AbstractJobProducerEndpoint {

  private static final Logger logger = LoggerFactory.getLogger(ConfigurablePublicationRestService.class);

  /* Gson is thread-safe so we use a single instance */
  private Gson gson = new Gson();

  private ConfigurablePublicationService service;
  private ServiceRegistry serviceRegistry;

  @Reference
  public void setService(final ConfigurablePublicationService service) {
    this.service = service;
  }

  @Reference
  public void setServiceRegistry(final ServiceRegistry serviceRegistry) {
    this.serviceRegistry = serviceRegistry;
  }

  @Override
  public JobProducer getService() {
    // The implementation is, of course, resolved by OSGi, so to be "clean", we hold a reference to just
    // the interface in this class, but at _this_ point, we assume it at least implements JobProducer.
    return (JobProducer) this.service;
  }

  @Override
  public ServiceRegistry getServiceRegistry() {
    return this.serviceRegistry;
  }

  @POST
  @Path("/replace")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Replace a media package in a publication channel",
      description = "Replace a media package in this publication channel"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the publication job")
  })
  public Response replace(
      @Parameter(description = "The media package", required = true)
      @FormParam("mediapackage") final String mediaPackageXml,
      @Parameter(description = "The channel name", required = true)
      @FormParam("channel") final String channel,
      @Parameter(description = "The media package elements to published", required = true)
      @FormParam("addElements") final String addElementsXml,
      @Parameter(
          description = "The identifiers of the media package elements to be retracted from the media package",
          required = true
      )
      @FormParam("retractElements") final String retractElements
  ) {
    Response response;
    final Job job;
    try {
      final MediaPackage mediaPackage = MediaPackageParser.getFromXml(mediaPackageXml);
      final Collection<? extends MediaPackageElement> addElements = new HashSet<>(
              MediaPackageElementParser.getArrayFromXml(addElementsXml));
      Set<String> retractElementsIds = gson.fromJson(retractElements, new TypeToken<Set<String>>() { }.getType());
      job = service.replace(mediaPackage, channel, addElements, retractElementsIds);
      response = Response.ok(new JaxbJob(job)).build();
    } catch (IllegalArgumentException e) {
      logger.warn("Unable to create a publication job", e);
      response = Response.status(Response.Status.BAD_REQUEST).build();
    } catch (Exception e) {
      logger.warn("Error publishing or retracting element", e);
      response = Response.serverError().build();
    }
    return response;
  }

  @POST
  @Path("/replacesync")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Replace a media package in a publication channel synchronously",
      description = "Synchronously replace a media package in this publication channel"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the publication")
  })
  public Response replaceSync(
      @Parameter(description = "The media package", required = true)
      @FormParam("mediapackage") final String mediaPackageXml,
      @Parameter(description = "The channel name", required = true)
      @FormParam("channel") final String channel,
      @Parameter(description = "The media package elements to published", required = true)
      @FormParam("addElements") final String addElementsXml,
      @Parameter(
          description = "The identifiers of the media package elements to be retracted from the media package",
          required = true
      )
      @FormParam("retractElements") final String retractElements
  ) {
    Response response;
    final Publication publication;
    try {
      final MediaPackage mediaPackage = MediaPackageParser.getFromXml(mediaPackageXml);
      final Collection<? extends MediaPackageElement> addElements = new HashSet<>(
          MediaPackageElementParser.getArrayFromXml(addElementsXml));
      Set<String> retractElementsIds = gson.fromJson(retractElements, new TypeToken<Set<String>>() { }.getType());
      publication = service.replaceSync(mediaPackage, channel, addElements, retractElementsIds);
      response = Response.ok(MediaPackageElementParser.getAsXml(publication)).build();
    } catch (Exception e) {
      logger.warn("Error publishing or retracting element", e);
      response = Response.serverError().build();
    }
    return response;
  }

}
