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

package org.opencastproject.helloworld.impl.endpoint;

import org.opencastproject.helloworld.api.HelloWorldService;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
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
 * The REST endpoint for the {@link HelloWorldService} service
 */
@Component(
    property = {
        "service.description=Hello World REST Endpoint",
        "opencast.service.type=org.opencastproject.helloworld",
        "opencast.service.path=/helloworld",
        "opencast.service.jobproducer=false"
    },
    immediate = true,
    service = HelloWorldRestEndpoint.class
)
@Path("/helloworld")
@Tag(
    name = "Hello World Service Endpoint",
    description = "This is a tutorial service."
)
@JaxrsResource
public class HelloWorldRestEndpoint {
  /** The logger */
  private static final Logger logger = LoggerFactory.getLogger(HelloWorldRestEndpoint.class);

  /** The rest docs */
  protected String docs;

  /** The service */
  protected HelloWorldService helloWorldService;

  /**
   * Simple example service call
   *
   * @return The Hello World statement
   * @throws Exception
   */
  @GET
  @Path("helloworld")
  @Produces(MediaType.TEXT_PLAIN)
  @Operation(
      summary = "Say hello to the world",
      description = "example service call"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Hello World"),
      @ApiResponse(responseCode = "500", description = "The underlying service could not output something.")
  })
  public Response helloWorld() throws Exception {
    logger.info("REST call for Hello World");
    return Response.ok().entity(helloWorldService.helloWorld()).build();
  }

  /**
   * Simple example service call with parameter
   *
   * @param name
   *          the optional name of the Person to greet
   * @return A Hello statement with optional name
   * @throws Exception
   */
  @GET
  @Path("helloname")
  @Produces(MediaType.TEXT_PLAIN)
  @Operation(
      summary = "Say hello to a name",
      description = "example service call with parameter"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Hello or Hello Name"),
      @ApiResponse(responseCode = "500", description = "The underlying service could not output something.")
  })
  public Response helloName(
      @Parameter(description = "name to output")
      @FormParam("name") String name
  ) throws Exception {
    logger.info("REST call for Hello Name");
    return Response.ok().entity(helloWorldService.helloName(name)).build();
  }

  @GET
  @Produces(MediaType.TEXT_HTML)
  @Path("docs")
  @Operation(
      summary = "Get the legacy REST documentation",
      description = "Requests to this path are answered by the REST servlet with a redirect to the legacy REST "
          + "documentation page of the service. Prefer the OpenAPI documentation."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "302", description = "Redirect to the legacy REST documentation.")
  })
  public String getDocs() {
    return docs;
  }

  @Reference
  public void setHelloWorldService(HelloWorldService service) {
    this.helloWorldService = service;
  }
}
