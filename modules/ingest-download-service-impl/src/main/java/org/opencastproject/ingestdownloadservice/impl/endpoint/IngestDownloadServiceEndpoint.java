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

package org.opencastproject.ingestdownloadservice.impl.endpoint;

import org.opencastproject.ingestdownloadservice.api.IngestDownloadService;
import org.opencastproject.job.api.JaxbJob;
import org.opencastproject.job.api.Job;
import org.opencastproject.job.api.JobProducer;
import org.opencastproject.mediapackage.MediaPackage;
import org.opencastproject.mediapackage.MediaPackageParser;
import org.opencastproject.rest.AbstractJobProducerEndpoint;
import org.opencastproject.serviceregistry.api.ServiceRegistry;
import org.opencastproject.serviceregistry.api.ServiceRegistryException;

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
 * The REST endpoint for the {@link IngestDownloadService} service
 */
@Path("/ingestdownload")
@Tag(
    name = "Ingest download REST endpoint",
    description = "The REST endpoint for the ingest download service."
)
@Component(
    immediate = true,
    service = IngestDownloadServiceEndpoint.class,
    property = {
        "service.description=Ingest download service Endpoint",
        "opencast.service.type=org.opencastproject.ingestdownload",
        "opencast.service.path=/ingestdownload",
        "opencast.service.jobproducer=true"
    }
)
@JaxrsResource
public class IngestDownloadServiceEndpoint extends AbstractJobProducerEndpoint {
  /** The logger */
  private static final Logger logger = LoggerFactory.getLogger(IngestDownloadServiceEndpoint.class);

  /** The service */
  private IngestDownloadService service;
  private ServiceRegistry serviceRegistry;

  @POST
  @Path("ingestdownload")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Download media package elements to the workspace",
      description = "Downloads mediapackage elements to workspace"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "An XML representation of the ingest download job"),
      @ApiResponse(responseCode = "500", description = "The ingest download job could not be created.")
  })
  public Response ingestdownload(
      @Parameter(description = "mediapackage as xml", required = true)
      @FormParam("mediapackage") String mediapackageString,
      @Parameter(
          description = "The source flavors separated by , (presenter/source,presentation/source). If it is missing "
              + "or empty, all flavors (*/*) are selected"
      )
      @FormParam("sourceFlavors") String sourceFlavors,
      @Parameter(description = "The source tags separated by , (archive,download)")
      @FormParam("sourceTags") String sourceTags,
      @Parameter(
          description = "Whether to delete the elements from the external working file repository (true or "
              + "false). If it is missing or empty, it means false"
      )
      @FormParam("deleteExternal") String deleteExternal,
      @Parameter(
          description = "Whether to select only the elements matching both the tags and the flavors (true or "
              + "false). If it is missing or empty, it means false"
      )
      @FormParam("tagsAndFlavor") String tagsAndFlavor
  ) throws Exception {
    logger.info("starting ingest-download Service");
    MediaPackage mediapackage = MediaPackageParser.getFromXml(mediapackageString);
    boolean boolTagsAndFlavor = false;
    boolean boolDeleteExternal = false;
    //set Defaults
    if (StringUtils.isEmpty(sourceFlavors)) {
      sourceFlavors = "*/*";
    }
    if (StringUtils.isNotEmpty(tagsAndFlavor)) {
      boolTagsAndFlavor = Boolean.parseBoolean(tagsAndFlavor);
    }
    if (StringUtils.isNotEmpty(deleteExternal)) {
      boolDeleteExternal = Boolean.parseBoolean(deleteExternal);
    }
    if (sourceTags == null) {
      sourceTags = "";
    }

    try {
      final Job retJob = service.ingestDownload(mediapackage ,sourceFlavors,sourceTags,boolDeleteExternal,
              boolTagsAndFlavor);
      return Response.ok().entity(new JaxbJob(retJob)).build();
    } catch (ServiceRegistryException e) {
      logger.warn("Unable to start IngestDownload: ", e);
      return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
    }
  }


  @Reference
  public void setIngestDownloadService(IngestDownloadService service) {
    this.service = service;
  }

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
}
