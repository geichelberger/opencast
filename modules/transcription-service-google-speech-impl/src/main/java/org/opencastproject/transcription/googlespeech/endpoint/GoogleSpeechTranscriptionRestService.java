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
package org.opencastproject.transcription.googlespeech.endpoint;

import org.opencastproject.job.api.JobProducer;
import org.opencastproject.rest.AbstractJobProducerEndpoint;
import org.opencastproject.serviceregistry.api.ServiceRegistry;
import org.opencastproject.transcription.api.TranscriptionServiceException;
import org.opencastproject.transcription.googlespeech.GoogleSpeechTranscriptionService;

import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

@Path("/transcripts/googlespeech")
@Tag(
    name = "Transcription Service REST Endpoint (uses Google Speech services)",
    description = "Uses external service to generate transcriptions of recordings."
)
@Component(
    immediate = true,
    service = GoogleSpeechTranscriptionRestService.class,
    property = {
        "service.description=Google Speech Transcription REST Endpoint",
        "opencast.service.type=org.opencastproject.transcription.googlespeech",
        "opencast.service.path=/transcripts/googlespeech",
        "opencast.service.jobproducer=true"
    }
)
@JaxrsResource
public class GoogleSpeechTranscriptionRestService extends AbstractJobProducerEndpoint {

  /**
   * The logger
   */
  private static final Logger logger = LoggerFactory.getLogger(GoogleSpeechTranscriptionRestService.class);

  /**
   * The transcription service
   */
  protected GoogleSpeechTranscriptionService service;

  /**
   * The service registry
   */
  protected ServiceRegistry serviceRegistry = null;

  @Activate
  public void activate(ComponentContext cc) {
  }

  @Reference
  public void setTranscriptionService(GoogleSpeechTranscriptionService service) {
    this.service = service;
  }

  @Reference
  public void setServiceRegistry(ServiceRegistry service) {
    this.serviceRegistry = service;
  }

  @Override
  public JobProducer getService() {
    return service;
  }

  @Override
  public ServiceRegistry getServiceRegistry() {
    return serviceRegistry;
  }

  @GET
  @Path("results")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the result of a transcription job",
      description = "Get JSON result of a submitted transcription job"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "If no errors"),
      @ApiResponse(responseCode = "500", description = "An error occurred")
  })
  // GET v1/operations/7022084740052439959
  public Response getTranscriptionResult(
      @Parameter(
          description = "job id of the submitted transcription (can be found in Google Speech database table)",
          required = true
      )
      @QueryParam("jobId") String jobId,
      @Context HttpServletRequest request
  ) throws TranscriptionServiceException, IOException {
    logger.debug("REST endpoint getTranscriptionResult called with job id: '{}'", jobId);
    String jobResult = null;
    try {
      jobResult = service.getTranscriptionResults(jobId);
    } catch (TranscriptionServiceException e) {
      logger.warn("Could not get transcription result for jobId : {}", jobId);
      return Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
    }
    return Response.ok(jobResult).build();
  }

  @GET
  @Path("status")
  @Produces(MediaType.TEXT_PLAIN)
  @Operation(
      summary = "Get the transcription status of a media package",
      description = "Get mediapackage transcription status"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "If no errors"),
      @ApiResponse(responseCode = "500", description = "An error occurred")
  })
  public Response getTranscriptionStatus(
      @Parameter(description = "The mediapackage identifier", required = true)
      @QueryParam("mediaPackageID") String mpId,
      @Context HttpServletRequest request
  ) throws TranscriptionServiceException {
    logger.debug("REST endpoint getTranscriptionStatus called with mediapackage id '{}'", mpId);
    String status = null;
    try {
      status = service.getTranscriptionStatus(mpId);
    } catch (TranscriptionServiceException e) {
      logger.warn("Could not get mediapackage transcription status for mediapackageId : {}", mpId);
      return Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
    }
    return Response.ok(status).build();
  }

}
