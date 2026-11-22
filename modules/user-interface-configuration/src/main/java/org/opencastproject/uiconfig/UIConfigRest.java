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

package org.opencastproject.uiconfig;

import static org.opencastproject.security.api.DefaultOrganization.DEFAULT_ORGANIZATION_ID;

import org.opencastproject.security.api.SecurityService;
import org.opencastproject.util.ConfigurationException;
import org.opencastproject.util.MimeTypes;
import org.opencastproject.util.NotFoundException;

import org.apache.commons.lang3.StringUtils;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.nio.file.Paths;
import java.util.Map;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * Serves UI configuration files via REST
 */
@Path("/ui/config")
@Tag(
    name = "UI Config Endpoint",
    description = "Serves the configuration of the UI"
)
@Component(
    property = {
        "service.description=UI Config REST Endpoint",
        "opencast.service.type=org.opencastproject.uiconfig",
        "opencast.service.path=/ui/config"
    },
    immediate = true,
    service = UIConfigRest.class
)
@JaxrsResource
public class UIConfigRest {
  /** The logger */
  private static final Logger logger = LoggerFactory.getLogger(UIConfigRest.class);

  /** Configuration key for the ui config folder */
  static final String UI_CONFIG_FOLDER_PROPERTY = "org.opencastproject.uiconfig.folder";
  static final String X_ACCEL_REDIRECT_PROPERTY = "X-Accel-Redirect";

  /** Default Path for the ui configuration folder (relative to ${karaf.etc}) */
  private static final String UI_CONFIG_FOLDER_DEFAULT = "ui-config";

  /** The currently used path to the configuration folder */
  private String uiConfigFolder = null;
  private String xAccelRedirect = null;

  /** The used SecurityService */
  private SecurityService securityService;

  @Reference
  protected void setSecurityService(SecurityService securityService) {
    this.securityService = securityService;
  }

  /**
   * OSGI callback for activating this component
   *
   * @param context
   *          the osgi component context
   */
  @Activate
  @Modified
  public void activate(BundleContext context, Map<String, String> properties)
          throws ConfigurationException, IOException {
    uiConfigFolder = properties.get(UI_CONFIG_FOLDER_PROPERTY);
    logger.debug("UI configuration folder configured as '{}'", uiConfigFolder);
    if (StringUtils.isNotEmpty(uiConfigFolder)) {
      uiConfigFolder = new File(uiConfigFolder).getCanonicalPath();
    } else {
      final String karafEtc = context.getProperty("karaf.etc");
      if (StringUtils.isBlank(karafEtc)) {
        throw new ConfigurationException(String.format(
            "%s not set and unable to fall back to default location based on ${karaf.etc}",
            UI_CONFIG_FOLDER_PROPERTY));
      }
      uiConfigFolder = new File(karafEtc, UI_CONFIG_FOLDER_DEFAULT).getCanonicalPath();
    }
    logger.debug("UI configuration folder set to '{}'", uiConfigFolder);

    xAccelRedirect = properties.get(X_ACCEL_REDIRECT_PROPERTY);
    logger.debug("X-Accel-Redirect path set to {}", xAccelRedirect);
  }

  @GET
  @Path("{component}/{filename : .+}")
  @Produces(MediaType.WILDCARD)
  @Operation(
      summary = "Get a UI configuration file",
      description = "Returns the requested configuration file (json, css, etc..)"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "the requested configuration file"),
      @ApiResponse(responseCode = "404", description = "if the configuration file doesn't exist")
  })
  public Response getConfigFile(
      @Parameter(description = "Name of the component, which the configuration file belongs to", required = true)
      @PathParam("component") String component,
      @Parameter(description = "Name of the configuration file", required = true)
      @PathParam("filename") String filename
  ) throws IOException, NotFoundException {
    final String orgId = securityService.getOrganization().getId();
    File configFile = Paths.get(uiConfigFolder, orgId, component, filename).toFile();

    try {
      final String basePath = new File(uiConfigFolder, orgId).getCanonicalPath() + File.separator;
      final String configFileCanPath = configFile.getCanonicalPath();

      // is configFile a subdirectory of basePath (additional directory traversal protection), if not stop
      if (!configFileCanPath.startsWith(basePath)) {
        logger.debug("Directory traversal prevented (trying to access '{}')", configFile.getPath());
        throw new AccessDeniedException(configFileCanPath);
      }

      // Falling back to default organization if file does not exist
      if (!configFile.exists()) {
        logger.debug("Falling back to default organization");
        configFile = Paths.get(uiConfigFolder, DEFAULT_ORGANIZATION_ID, component, filename).toFile();
      }

      if (xAccelRedirect != null) {
        final String relative = Paths.get(uiConfigFolder).relativize(configFile.toPath()).toString();
        return Response.noContent()
            .header("X-Accel-Redirect", Paths.get(xAccelRedirect, relative).toString())
            .build();
      }

      // It is safe to pass the InputStream without closing it, JAX-RS takes care of that
      return Response.ok(new FileInputStream(configFile))
              .header("Content-Length", configFile.length())
              .header("Content-Type", MimeTypes.getMimeType(filename))
              .build();
    } catch (FileNotFoundException e) {
      logger.debug("Could not find requested configuration file '{}'", configFile.getPath(), e);
      throw new NotFoundException();
    }
  }

}
