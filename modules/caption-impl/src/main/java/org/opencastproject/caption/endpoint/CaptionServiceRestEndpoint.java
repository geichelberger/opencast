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

package org.opencastproject.caption.endpoint;

import org.opencastproject.caption.api.CaptionService;
import org.opencastproject.job.api.JaxbJob;
import org.opencastproject.job.api.Job;
import org.opencastproject.job.api.JobProducer;
import org.opencastproject.mediapackage.Catalog;
import org.opencastproject.mediapackage.MediaPackageElement;
import org.opencastproject.mediapackage.MediaPackageElementParser;
import org.opencastproject.rest.AbstractJobProducerEndpoint;
import org.opencastproject.serviceregistry.api.ServiceRegistry;
import org.opencastproject.util.XmlSafeParser;

import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.StringWriter;

import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.transform.Transformer;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * Rest endpoint for {@link CaptionService}.
 */
@Path("/caption")
@Tag(
    name = "Caption Service",
    description = "This service enables conversion from one caption format to another."
)
@Component(
    immediate = true,
    service = CaptionServiceRestEndpoint.class,
    property = {
        "service.description=Caption REST Endpoint",
        "opencast.service.type=org.opencastproject.caption",
        "opencast.service.path=/caption",
        "opencast.service.jobproducer=true"
    }
)
@JaxrsResource
public class CaptionServiceRestEndpoint extends AbstractJobProducerEndpoint {

  /** The logger */
  private static final Logger logger = LoggerFactory.getLogger(CaptionServiceRestEndpoint.class);

  /** The caption service */
  protected CaptionService service;

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

  /**
   * Sets the caption service
   *
   * @param service
   *          the caption service to set
   */
  @Reference(
      cardinality = ReferenceCardinality.OPTIONAL,
      policy = ReferencePolicy.DYNAMIC,
      unbind = "unsetCaptionService"
  )
  protected void setCaptionService(CaptionService service) {
    this.service = service;
  }

  /**
   * Removes the caption service
   *
   * @param service
   *          the caption service to remove
   */
  protected void unsetCaptionService(CaptionService service) {
    if (this.service == service) {
      this.service = null;
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
   * Convert captions in catalog from one format to another.
   *
   * @param inputType
   *          input format
   * @param outputType
   *          output format
   * @param catalogAsXml
   *          catalog containing captions
   * @param lang
   *          caption language
   * @return a Response containing receipt of for conversion
   */
  @POST
  @Path("convert")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Convert captions from one format to another",
      description = "Convert captions from one format to another."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The conversion job as XML."),
      @ApiResponse(responseCode = "400", description = "The captions could not be parsed or are not a catalog."),
      @ApiResponse(responseCode = "500", description = "The conversion job could not be created.")
  })
  public Response convert(
      @Parameter(
          description = "Caption input format (for example: dfxp, subrip,...).",
          schema = @Schema(example = "dfxp")
      )
      @FormParam("input") String inputType,
      @Parameter(
          description = "Caption output format (for example: dfxp, subrip,...).",
          schema = @Schema(example = "subrip")
      )
      @FormParam("output") String outputType,
      @Parameter(description = "Captions to be converted.", required = true)
      @FormParam("captions") String catalogAsXml,
      @Parameter(
          description = "Caption language (for those formats that store such information). If blank, the "
              + "conversion is done without a language.",
          schema = @Schema(example = "en")
      )
      @FormParam("language") String lang
  ) {
    MediaPackageElement element;
    try {
      element = MediaPackageElementParser.getFromXml(catalogAsXml);
      if (!Catalog.TYPE.equals(element.getElementType())) {
        return Response.status(Response.Status.BAD_REQUEST).entity("Captions must be of type catalog.").build();
      }
    } catch (Exception e) {
      logger.info("Unable to parse serialized captions");
      return Response.status(Response.Status.BAD_REQUEST).build();
    }

    try {
      Job job;
      if (StringUtils.isNotBlank(lang)) {
        job = service.convert((Catalog) element, inputType, outputType, lang);
      } else {
        job = service.convert((Catalog) element, inputType, outputType);
      }
      return Response.ok().entity(new JaxbJob(job)).build();
    } catch (Exception e) {
      logger.error("Unable to convert captions: {}", e.getMessage());
      return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
    }
  }

  /**
   * Parses captions in catalog for language information.
   *
   * @param inputType
   *          caption format
   * @param catalogAsXml
   *          catalog containing captions
   * @return a Response containing XML with language information
   */
  @POST
  @Path("languages")
  @Produces(MediaType.TEXT_XML)
  @Operation(
      summary = "Get the languages of a caption catalog",
      description = "Get information about languages in caption catalog (if such information is available)."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The languages of the catalog as XML."),
      @ApiResponse(responseCode = "400", description = "The captions are not a catalog."),
      @ApiResponse(responseCode = "500", description = "The captions could not be parsed or examined.")
  })
  public Response languages(
      @Parameter(
          description = "Caption input format (for example: dfxp, subrip,...).",
          schema = @Schema(example = "dfxp")
      )
      @FormParam("input") String inputType,
      @Parameter(description = "Captions to be examined.", required = true)
      @FormParam("captions") String catalogAsXml
  ) {
    try {
      MediaPackageElement element = MediaPackageElementParser.getFromXml(catalogAsXml);
      if (!Catalog.TYPE.equals(element.getElementType())) {
        return Response.status(Response.Status.BAD_REQUEST).entity("Captions must be of type catalog").build();
      }

      String[] languageArray = service.getLanguageList((Catalog) element, inputType);

      // build response
      DocumentBuilder docBuilder = XmlSafeParser.newDocumentBuilderFactory().newDocumentBuilder();
      Document doc = docBuilder.newDocument();
      Element root = doc.createElement("languages");
      root.setAttribute("type", inputType);
      root.setAttribute("url", element.getURI().toString());
      for (String lang : languageArray) {
        Element language = doc.createElement("language");
        language.appendChild(doc.createTextNode(lang));
        root.appendChild(language);
      }

      DOMSource domSource = new DOMSource(root);
      StringWriter writer = new StringWriter();
      StreamResult result = new StreamResult(writer);
      Transformer transformer = XmlSafeParser.newTransformerFactory().newTransformer();
      transformer.transform(domSource, result);

      return Response.status(Response.Status.OK).entity(writer.toString()).build();
    } catch (Exception e) {
      logger.error("Unable to parse captions: {}", e.getMessage());
      return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
    }
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
