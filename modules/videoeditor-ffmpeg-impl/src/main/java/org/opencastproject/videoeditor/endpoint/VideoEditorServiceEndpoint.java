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

package org.opencastproject.videoeditor.endpoint;

import org.opencastproject.job.api.JaxbJobList;
import org.opencastproject.job.api.Job;
import org.opencastproject.job.api.JobProducer;
import org.opencastproject.rest.AbstractJobProducerEndpoint;
import org.opencastproject.serviceregistry.api.ServiceRegistry;
import org.opencastproject.smil.api.SmilService;
import org.opencastproject.smil.entity.api.Smil;
import org.opencastproject.videoeditor.api.VideoEditorService;

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
 * VideoEditorService REST Endpoint.
 */
@Path("/videoeditor")
@Tag(
    name = "Video Editor Service REST Endpoint",
    description = "Video Editor Service consumes a smil document and create corresponding video files."
)
@Component(
    immediate = true,
    service = VideoEditorServiceEndpoint.class,
    property = {
        "service.description=Video Editor Service REST Endpoint",
        "opencast.service.type=org.opencastproject.videoeditor",
        "opencast.service.path=/videoeditor",
        "opencast.service.jobproducer=true"
    }
)
@JaxrsResource
public class VideoEditorServiceEndpoint extends AbstractJobProducerEndpoint {

  private ServiceRegistry serviceRegistry;
  private VideoEditorService videoEditorService;
  private SmilService smilService;

  @POST
  @Path("/process-smil")
  @Produces({MediaType.APPLICATION_XML})
  @Operation(
      summary = "Process a SMIL file",
      description = "Create smil processing jobs."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Smil processing jobs created successfully."),
      @ApiResponse(responseCode = "500", description = "Internal server error.")
  })
  public Response processSmil(
      @Parameter(description = "Smil document to process.", required = true)
      @FormParam("smil") String smilStr
  ) {
    Smil smil;
    try {
      smil = smilService.fromXml(smilStr).getSmil();
      List<Job> jobs = videoEditorService.processSmil(smil);
      return Response.ok(new JaxbJobList(jobs)).build();
    } catch (Exception ex) {
      return Response.serverError().entity(ex.getMessage()).build();
    }
  }

  @Override
  public JobProducer getService() {
    if (videoEditorService instanceof JobProducer) {
      return (JobProducer) videoEditorService;
    } else {
      return null;
    }
  }

  @Override
  public ServiceRegistry getServiceRegistry() {
    return serviceRegistry;
  }

  @Reference
  public void setVideoEditorService(VideoEditorService videoEditorService) {
    this.videoEditorService = videoEditorService;
  }

  @Reference
  public void setServiceRegistry(ServiceRegistry serviceRegistry) {
    this.serviceRegistry = serviceRegistry;
  }

  @Reference
  public void setSmilService(SmilService smilService) {
    this.smilService = smilService;
  }
}
