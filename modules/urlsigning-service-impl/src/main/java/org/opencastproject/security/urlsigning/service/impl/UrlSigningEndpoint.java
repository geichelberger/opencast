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
package org.opencastproject.security.urlsigning.service.impl;

import static javax.servlet.http.HttpServletResponse.SC_BAD_REQUEST;
import static org.apache.commons.lang3.StringUtils.trimToNull;

import org.opencastproject.security.urlsigning.exception.UrlSigningException;
import org.opencastproject.security.urlsigning.service.UrlSigningService;

import org.joda.time.DateTime;
import org.joda.time.DateTimeConstants;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;

import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

@Path("/signing")
@Tag(
    name = "URL Signing Endpoint",
    description = "This is a testing endpoint to play around with the URL Signing Service"
)
@Component(
    immediate = true,
    service = UrlSigningEndpoint.class,
    property = {
        "service.description=Url Signing REST Endpoint",
        "opencast.service.type=org.opencastproject.security.urlsigning.testing",
        "opencast.service.path=/signing",
        "opencast.service.publish=false",
        "opencast.service.jobproducer=false"
    }
)
@JaxrsResource
public class UrlSigningEndpoint {

  private UrlSigningService signingService;

  /** OSGi DI callback */
  @Reference
  void setUrlSigningService(UrlSigningService signingService) {
    this.signingService = signingService;
  }

  @GET
  @Produces({ MediaType.TEXT_PLAIN })
  @Path("accepts")
  @Operation(
      summary = "Check whether a URL can be signed",
      description = "Checks if the signing service accepts to sign the URL"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "'true' or 'false'")
  })
  public Response accepts(
      @Parameter(description = "The URL to sign", required = true)
      @QueryParam("baseUrl") final String baseUrl
  ) {
    if (signingService.accepts(baseUrl)) {
      return Response.ok(Boolean.TRUE.toString()).build();
    } else {
      return Response.ok(Boolean.FALSE.toString()).build();
    }
  }

  @GET
  @Produces({ MediaType.TEXT_PLAIN })
  @Path("sign")
  @Operation(
      summary = "Sign a URL",
      description = "Return a signed URL"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The signed URL."),
      @ApiResponse(responseCode = "400", description = "The signing service does not accept the URL or signing failed.")
  })
  public Response sign(
      @Parameter(description = "The URL to sign", required = true)
      @QueryParam("baseUrl") final String baseUrl,
      @Parameter(
          description = "The UNIX epoch time until when a signed URL should remain valid",
          required = true,
          example = "0"
      )
      @QueryParam("validUntil") final long validUntil,
      @Parameter(
          description = "The UNIX epoch time from when a signed URL should become valid. If 0, the URL is valid "
              + "immediately",
          example = "0"
      )
      @QueryParam("validFrom") @DefaultValue("0") long validFrom,
      @Parameter(
          description = "The IP address of the user that is allowed to access the resource. If blank, the access "
              + "is not restricted to an address",
          example = ""
      )
      @QueryParam("ipAddr") @DefaultValue("") String ipAddr
  ) {
    try {
      if (signingService.accepts(baseUrl)) {
        final String signedUrl = signingService.sign(baseUrl, new DateTime(validUntil
                * DateTimeConstants.MILLIS_PER_SECOND), (validFrom > 0 ? new DateTime(validFrom
                * DateTimeConstants.MILLIS_PER_SECOND) : null), trimToNull(ipAddr));
        return Response.ok(signedUrl).build();
      } else {
        return Response.status(SC_BAD_REQUEST).build();
      }
    } catch (UrlSigningException e) {
      return Response.status(SC_BAD_REQUEST).entity(e.getMessage()).build();
    }
  }

}
