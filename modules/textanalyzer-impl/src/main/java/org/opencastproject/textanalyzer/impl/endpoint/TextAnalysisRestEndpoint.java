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

package org.opencastproject.textanalyzer.impl.endpoint;

import org.opencastproject.job.api.JaxbJob;
import org.opencastproject.job.api.Job;
import org.opencastproject.job.api.JobProducer;
import org.opencastproject.mediapackage.Attachment;
import org.opencastproject.mediapackage.MediaPackageElement;
import org.opencastproject.mediapackage.MediaPackageElementParser;
import org.opencastproject.rest.AbstractJobProducerEndpoint;
import org.opencastproject.serviceregistry.api.ServiceRegistry;
import org.opencastproject.textanalyzer.api.TextAnalyzerService;

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
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * The REST endpoint for MediaAnalysisServices
 */
@Path("/analysis/text")
@Tag(
    name = "Text Analysis Service",
    description = "This service enables conversion from one caption format to another."
)
@Component(
    immediate = false,
    service = TextAnalysisRestEndpoint.class,
    property = {
        "service.description=Text Analysis REST Endpoint",
        "opencast.service.type=org.opencastproject.textanalyzer",
        "opencast.service.path=/analysis/text",
        "opencast.service.jobproducer=true"
    }
)
@JaxrsResource
public class TextAnalysisRestEndpoint extends AbstractJobProducerEndpoint {

  /** The logging facility */
  private static final Logger logger = LoggerFactory.getLogger(TextAnalysisRestEndpoint.class);

  /** The text analyzer */
  protected TextAnalyzerService service;

  /** The service registry */
  protected ServiceRegistry serviceRegistry = null;

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

  @POST
  @Produces(MediaType.TEXT_XML)
  @Path("")
  @Operation(
      summary = "Analyze an image for text",
      description = "Submit a track for analysis."
  )
  @ApiResponses({
      @ApiResponse(
          responseCode = "200",
          description = "OK, The receipt to use when polling for the resulting mpeg7 catalog."
      ),
      @ApiResponse(responseCode = "400", description = "The argument cannot be parsed into a media package element."),
      @ApiResponse(responseCode = "503", description = "The service is unavailable at the moment.")
  })
  public Response analyze(
      @Parameter(description = "The image to analyze for text.", required = true)
      @FormParam("image") String image
  ) {
    if (service == null) {
      throw new WebApplicationException(Status.SERVICE_UNAVAILABLE);
    }
    try {
      MediaPackageElement element = MediaPackageElementParser.getFromXml(image);
      if (!(element instanceof Attachment)) {
        throw new WebApplicationException(Status.BAD_REQUEST);
      }
      Job job = service.extract((Attachment) element);
      return Response.ok(new JaxbJob(job)).build();
    } catch (Exception e) {
      logger.info(e.getMessage(), e);
      return Response.serverError().build();
    }
  }

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
   * Sets the text analyzer
   *
   * @param textAnalyzer
   *          the text analyzer
   */
  @Reference
  protected void setTextAnalyzer(TextAnalyzerService textAnalyzer) {
    this.service = textAnalyzer;
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

}
