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

package org.opencastproject.series.endpoint;

import static javax.ws.rs.core.Response.Status.BAD_REQUEST;
import static javax.ws.rs.core.Response.Status.CREATED;
import static javax.ws.rs.core.Response.Status.INTERNAL_SERVER_ERROR;
import static javax.ws.rs.core.Response.Status.NOT_FOUND;
import static javax.ws.rs.core.Response.Status.NO_CONTENT;
import static org.opencastproject.metadata.dublincore.DublinCore.PROPERTY_IDENTIFIER;

import org.opencastproject.mediapackage.EName;
import org.opencastproject.metadata.dublincore.DublinCore;
import org.opencastproject.metadata.dublincore.DublinCoreCatalog;
import org.opencastproject.metadata.dublincore.DublinCoreCatalogService;
import org.opencastproject.metadata.dublincore.DublinCores;
import org.opencastproject.rest.RestConstants;
import org.opencastproject.security.api.AccessControlList;
import org.opencastproject.security.api.AccessControlParser;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.security.api.UnauthorizedException;
import org.opencastproject.series.api.Series;
import org.opencastproject.series.api.SeriesException;
import org.opencastproject.series.api.SeriesService;
import org.opencastproject.systems.OpencastConstants;
import org.opencastproject.util.NotFoundException;
import org.opencastproject.util.RestUtil.R;
import org.opencastproject.util.UrlSupport;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.DELETE;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * REST endpoint for Series Service.
 *
 */
@Path("/series")
@Tag(
    name = "Series Service",
    description = "This service creates, edits and retrieves and helps managing series."
)
@Component(
    immediate = true,
    service = SeriesRestService.class,
    property = {
        "service.description=Series REST Endpoint",
        "opencast.service.type=org.opencastproject.series",
        "opencast.service.path=/series"
    }
)
@JaxrsResource
public class SeriesRestService {

  private static final String SERIES_ELEMENT_CONTENT_TYPE_PREFIX = "series/";

  private static final Gson gson = new Gson();

  /** Logging utility */
  private static final Logger logger = LoggerFactory.getLogger(SeriesRestService.class);

  /** Series Service */
  private SeriesService seriesService;

  /** Dublin Core Catalog service */
  private DublinCoreCatalogService dcService;

  /** The security service */
  private SecurityService securityService;

  /** Default server URL */
  protected String serverUrl = "http://localhost:8080";

  /** Service url */
  protected String serviceUrl = null;

  /** Default number of items on page */
  private static final int DEFAULT_LIMIT = 20;

  /** Suffix to mark descending ordering of results */
  public static final String DESCENDING_SUFFIX = "_DESC";

  private static final String SAMPLE_DUBLIN_CORE = "<?xml version=\"1.0\"?>\n"
      + "<dublincore xmlns=\"http://www.opencastproject.org/xsd/1.0/dublincore/\" "
      + "    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n"
      + "    xsi:schemaLocation=\"http://www.opencastproject.org http://www.opencastproject.org/schema.xsd\" "
      + "    xmlns:dc=\"http://purl.org/dc/elements/1.1/\"\n"
      + "    xmlns:dcterms=\"http://purl.org/dc/terms/\" "
      + "    xmlns:oc=\"http://www.opencastproject.org/matterhorn/\">\n\n"
      + "  <dcterms:title xml:lang=\"en\">\n"
      + "    Land and Vegetation: Key players on the Climate Scene\n"
      + "  </dcterms:title>\n"
      + "  <dcterms:subject>"
      + "    climate, land, vegetation\n"
      + "  </dcterms:subject>\n"
      + "  <dcterms:description xml:lang=\"en\">\n"
      + "    Introduction lecture from the Institute for\n"
      + "    Atmospheric and Climate Science.\n"
      + "  </dcterms:description>\n"
      + "  <dcterms:publisher>\n"
      + "    ETH Zurich, Switzerland\n"
      + "  </dcterms:publisher>\n"
      + "  <dcterms:identifier>\n"
      + "    10.0000/5819\n"
      + "  </dcterms:identifier>\n"
      + "  <dcterms:modified xsi:type=\"dcterms:W3CDTF\">\n"
      + "    2007-12-05\n"
      + "  </dcterms:modified>\n"
      + "  <dcterms:format xsi:type=\"dcterms:IMT\">\n"
      + "    video/x-dv\n"
      + "  </dcterms:format>\n"
      + "</dublincore>";

  private static final String SAMPLE_ACCESS_CONTROL_LIST =
      "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
          + "<acl xmlns=\"http://org.opencastproject.security\">\n"
          + "  <ace>\n"
          + "    <role>admin</role>\n"
          + "    <action>delete</action>\n"
          + "    <allow>true</allow>\n"
          + "  </ace>\n"
          + "</acl>";

  /**
   * OSGi callback for setting series service.
   *
   * @param seriesService
   */
  @Reference
  public void setService(SeriesService seriesService) {
    this.seriesService = seriesService;
  }

  /**
   * OSGi callback for setting Dublin Core Catalog service.
   *
   * @param dcService
   */
  @Reference
  public void setDublinCoreService(DublinCoreCatalogService dcService) {
    this.dcService = dcService;
  }

  /** OSGi callback for the security service */
  @Reference
  public void setSecurityService(SecurityService securityService) {
    this.securityService = securityService;
  }


  /**
   * Activates REST service.
   *
   * @param cc
   *          ComponentContext
   */
  @Activate
  public void activate(ComponentContext cc) {
    if (cc == null) {
      this.serverUrl = "http://localhost:8080";
    } else {
      String ccServerUrl = cc.getBundleContext().getProperty(OpencastConstants.SERVER_URL_PROPERTY);
      logger.debug("Configured server url is {}", ccServerUrl);
      if (ccServerUrl == null) {
        this.serverUrl = "http://localhost:8080";
      } else {
        this.serverUrl = ccServerUrl;
      }
    }
    serviceUrl = (String) cc.getProperties().get(RestConstants.SERVICE_PATH_PROPERTY);
  }

  public String getSeriesXmlUrl(String seriesId) {
    return UrlSupport.concat(serverUrl, serviceUrl, seriesId + ".xml");
  }

  public String getSeriesJsonUrl(String seriesId) {
    return UrlSupport.concat(serverUrl, serviceUrl, seriesId + ".json");
  }

  @GET
  @Produces(MediaType.TEXT_XML)
  @Path("{seriesID:.+}.xml")
  @Operation(
      summary = "Get a series as XML",
      description = "Returns the series with the given identifier"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The series dublin core."),
      @ApiResponse(responseCode = "404", description = "No series with this identifier was found."),
      @ApiResponse(responseCode = "403", description = "You do not have permission to view this series."),
      @ApiResponse(
          responseCode = "401",
          description = "You do not have permission to view this series. Maybe you need to authenticate."
      ),
      @ApiResponse(responseCode = "500", description = "The series could not be retrieved.")
  })
  public Response getSeriesXml(
      @Parameter(description = "The series identifier", required = true)
      @PathParam("seriesID") String seriesID
  ) {
    logger.debug("Series Lookup: {}", seriesID);
    try {
      DublinCoreCatalog dc = this.seriesService.getSeries(seriesID);
      return Response.ok(dc.toXmlString()).build();
    } catch (NotFoundException e) {
      return Response.status(Response.Status.NOT_FOUND).build();
    } catch (UnauthorizedException e) {
      logger.warn("permission exception retrieving series");
      // TODO this should be an 403 (Forbidden) if the user is logged in
      throw new WebApplicationException(Response.Status.UNAUTHORIZED);
    } catch (Exception e) {
      logger.error("Could not retrieve series: {}", e.getMessage());
      throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("{seriesID:.+}.json")
  @Operation(
      summary = "Get a series as JSON",
      description = "Returns the series with the given identifier"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The series dublin core."),
      @ApiResponse(responseCode = "404", description = "No series with this identifier was found."),
      @ApiResponse(
          responseCode = "401",
          description = "You do not have permission to view this series. Maybe you need to authenticate."
      ),
      @ApiResponse(responseCode = "500", description = "The series could not be retrieved.")
  })
  public Response getSeriesJSON(
      @Parameter(description = "The series identifier", required = true)
      @PathParam("seriesID") String seriesID
  ) {
    logger.debug("Series Lookup: {}", seriesID);
    try {
      DublinCoreCatalog dc = this.seriesService.getSeries(seriesID);
      return Response.ok(dc.toJson()).build();
    } catch (NotFoundException e) {
      return Response.status(Response.Status.NOT_FOUND).build();
    } catch (UnauthorizedException e) {
      logger.warn("permission exception retrieving series");
      // TODO this should be an 403 (Forbidden) if the user is logged in
      throw new WebApplicationException(Response.Status.UNAUTHORIZED);
    } catch (Exception e) {
      logger.error("Could not retrieve series: {}", e.getMessage());
      throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  @GET
  @Produces(MediaType.TEXT_XML)
  @Path("/{seriesID:.+}/acl.xml")
  @Operation(
      summary = "Get the ACL of a series as XML",
      description = "Returns the access control list for the series with the given identifier"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The access control list."),
      @ApiResponse(responseCode = "404", description = "No series with this identifier was found.")
  })
  public Response getSeriesAccessControlListXml(
      @Parameter(description = "The series identifier", required = true)
      @PathParam("seriesID") String seriesID
  ) {
    return getSeriesAccessControlList(seriesID);
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("/{seriesID:.+}/acl.json")
  @Operation(
      summary = "Get the ACL of a series as JSON",
      description = "Returns the access control list for the series with the given identifier"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The access control list."),
      @ApiResponse(responseCode = "404", description = "No series with this identifier was found.")
  })
  public Response getSeriesAccessControlListJson(
      @Parameter(description = "The series identifier", required = true)
      @PathParam("seriesID") String seriesID
  ) {
    return getSeriesAccessControlList(seriesID);
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("/allInRangeAdministrative.json")
  @Operation(
      summary = "Get all series in a time range",
      description = "Internal API! Returns all series (included deleted ones!) in the given "
          + "range 'from' (inclusive) .. 'to' (exclusive). Returns at most 'limit' many series. "
          + "Can only be used as administrator!"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "All series in the range"),
      @ApiResponse(responseCode = "400", description = "if the given parameters are invalid"),
      @ApiResponse(responseCode = "401", description = "If the user is not an administrator")
  })
  public Response getAllInRangeAdministrative(
      @Parameter(
          description = "Start of date range (inclusive) in milliseconds "
              + "since 1970-01-01T00:00:00Z. Has to be >=0.",
          required = true
      )
      @QueryParam("from") Long from,
      @Parameter(
          description = "End of date range (exclusive) in milliseconds "
              + "since 1970-01-01T00:00:00Z. Has to be > 'from'."
      )
      @QueryParam("to") Long to,
      @Parameter(description = "Maximum number of series to be returned. Has to be >0.", required = true)
      @QueryParam("limit") Integer limit
  ) throws UnauthorizedException {
    // Parameter error handling
    if (from == null) {
      return badRequestAllInRange("Required parameter 'from' not specified");
    }
    if (limit == null) {
      return badRequestAllInRange("Required parameter 'limit' not specified");
    }
    if (from < 0) {
      return badRequestAllInRange("Parameter 'from' < 0, but it has to be >= 0");
    }
    if (to != null && to <= from) {
      return badRequestAllInRange("Parameter 'to' <= 'from', but that is not allowed");
    }
    if (limit <= 0) {
      return badRequestAllInRange("Parameter 'limit' <= 0, but it has to be > 0");
    }

    try {
      final List<Series> series = seriesService.getAllForAdministrativeRead(
          new Date(from),
          Optional.ofNullable(to).map(millis -> new Date(millis)),
          limit);

      return Response.ok(gson.toJson(series)).build();
    } catch (SeriesException e) {
      logger.error("Unexpected exception in getAllInRangeAdministrative", e);
      return Response.status(INTERNAL_SERVER_ERROR)
          .entity("internal server error")
          .build();
    }
  }

  /**
   * Returns a {@code Response} object representing a BAD_REQUEST to `allInRangeAdministrative`
   * with the given message as body. Also logs the message.
   */
  private static Response badRequestAllInRange(String msg) {
    logger.debug("Bad request to /series/allInRangeAdministrative: {}", msg);
    return Response.status(BAD_REQUEST).entity(msg).build();
  }

  /**
   * Retrieves ACL associated with series.
   *
   * @param seriesID
   *          series of which ACL should be retrieved
   * @return
   */
  private Response getSeriesAccessControlList(String seriesID) {
    logger.debug("Series ACL lookup: {}", seriesID);
    try {
      AccessControlList acl = seriesService.getSeriesAccessControl(seriesID);
      return Response.ok(acl).build();
    } catch (NotFoundException e) {
      return Response.status(NOT_FOUND).build();
    } catch (SeriesException e) {
      logger.error("Could not retrieve series ACL: {}", e.getMessage());
    }
    throw new WebApplicationException(INTERNAL_SERVER_ERROR);
  }

  private void addDcData(final DublinCoreCatalog dc, final String field, final String value) {
    if (StringUtils.isNotBlank(value)) {
      EName en = new EName(DublinCore.TERMS_NS_URI, field);
      dc.add(en, value);
    }
  }

  @POST
  @Path("/")
  @Operation(
      summary = "Update a series",
      description = "Updates a series"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "400", description = "The required form params were missing in the request."),
      @ApiResponse(responseCode = "204", description = "The access control list has been updated."),
      @ApiResponse(responseCode = "401", description = "If the current user is not authorized to perform this action"),
      @ApiResponse(responseCode = "201", description = "The access control list has been created."),
      @ApiResponse(responseCode = "500", description = "The series could not be stored.")
  })
  public Response addOrUpdateSeries(
      @Parameter(
          description = "The series document. Will take precedence over metadata fields",
          schema = @Schema(example = SAMPLE_DUBLIN_CORE)
      )
      @FormParam("series") String series,
      @Parameter(
          description = "The access control list for the series",
          schema = @Schema(example = SAMPLE_ACCESS_CONTROL_LIST)
      )
      @FormParam("acl") String accessControl,
      @Parameter(description = "Series metadata value")
      @FormParam("accessRights") String dcAccessRights,
      @Parameter(description = "Series metadata value")
      @FormParam("available") String dcAvailable,
      @Parameter(description = "Series metadata value")
      @FormParam("contributor") String dcContributor,
      @Parameter(description = "Series metadata value")
      @FormParam("coverage") String dcCoverage,
      @Parameter(description = "Series metadata value")
      @FormParam("created") String dcCreated,
      @Parameter(description = "Series metadata value")
      @FormParam("creator") String dcCreator,
      @Parameter(description = "Series metadata value")
      @FormParam("date") String dcDate,
      @Parameter(description = "Series metadata value")
      @FormParam("description") String dcDescription,
      @Parameter(description = "Series metadata value")
      @FormParam("extent") String dcExtent,
      @Parameter(description = "Series metadata value")
      @FormParam("format") String dcFormat,
      @Parameter(description = "Series metadata value")
      @FormParam("identifier") String dcIdentifier,
      @Parameter(description = "Series metadata value")
      @FormParam("isPartOf") String dcIsPartOf,
      @Parameter(description = "Series metadata value")
      @FormParam("isReferencedBy") String dcIsReferencedBy,
      @Parameter(description = "Series metadata value")
      @FormParam("isReplacedBy") String dcIsReplacedBy,
      @Parameter(description = "Series metadata value")
      @FormParam("language") String dcLanguage,
      @Parameter(description = "Series metadata value")
      @FormParam("license") String dcLicense,
      @Parameter(description = "Series metadata value")
      @FormParam("publisher") String dcPublisher,
      @Parameter(description = "Series metadata value")
      @FormParam("relation") String dcRelation,
      @Parameter(description = "Series metadata value")
      @FormParam("replaces") String dcReplaces,
      @Parameter(description = "Series metadata value")
      @FormParam("rights") String dcRights,
      @Parameter(description = "Series metadata value")
      @FormParam("rightsHolder") String dcRightsHolder,
      @Parameter(description = "Series metadata value")
      @FormParam("source") String dcSource,
      @Parameter(description = "Series metadata value")
      @FormParam("spatial") String dcSpatial,
      @Parameter(description = "Series metadata value")
      @FormParam("subject") String dcSubject,
      @Parameter(description = "Series metadata value")
      @FormParam("temporal") String dcTemporal,
      @Parameter(description = "Series metadata value")
      @FormParam("title") String dcTitle,
      @Parameter(description = "Series metadata value")
      @FormParam("type") String dcType,
      @Parameter(
          description = "If true the series ACL will take precedence over any existing episode ACL",
          schema = @Schema(example = "false")
      )
      @DefaultValue("false") @FormParam("override") boolean override
  ) throws UnauthorizedException {
    DublinCoreCatalog dc;
    if (StringUtils.isNotBlank(series)) {
      try {
        dc = this.dcService.load(new ByteArrayInputStream(series.getBytes(StandardCharsets.UTF_8)));
      } catch (UnsupportedEncodingException e1) {
        logger.error("Could not deserialize dublin core catalog", e1);
        throw new WebApplicationException(INTERNAL_SERVER_ERROR);
      } catch (IOException e1) {
        logger.warn("Could not deserialize dublin core catalog", e1);
        return Response.status(BAD_REQUEST).build();
      }
    } else if (StringUtils.isNotBlank(dcTitle)) {
      dc = DublinCores.mkOpencastSeries().getCatalog();
      addDcData(dc, "accessRights", dcAccessRights);
      addDcData(dc, "available", dcAvailable);
      addDcData(dc, "contributor", dcContributor);
      addDcData(dc, "coverage", dcCoverage);
      addDcData(dc, "created", dcCreated);
      addDcData(dc, "creator", dcCreator);
      addDcData(dc, "date", dcDate);
      addDcData(dc, "description", dcDescription);
      addDcData(dc, "extent", dcExtent);
      addDcData(dc, "format", dcFormat);
      addDcData(dc, "identifier", dcIdentifier);
      addDcData(dc, "isPartOf", dcIsPartOf);
      addDcData(dc, "isReferencedBy", dcIsReferencedBy);
      addDcData(dc, "isReplacedBy", dcIsReplacedBy);
      addDcData(dc, "language", dcLanguage);
      addDcData(dc, "license", dcLicense);
      addDcData(dc, "publisher", dcPublisher);
      addDcData(dc, "relation", dcRelation);
      addDcData(dc, "replaces", dcReplaces);
      addDcData(dc, "rights", dcRights);
      addDcData(dc, "rightsHolder", dcRightsHolder);
      addDcData(dc, "source", dcSource);
      addDcData(dc, "spatial", dcSpatial);
      addDcData(dc, "subject", dcSubject);
      addDcData(dc, "temporal", dcTemporal);
      addDcData(dc, "title", dcTitle);
      addDcData(dc, "type", dcType);
    } else {
      return Response.status(BAD_REQUEST).entity("Required series metadata not provided").build();
    }
    AccessControlList acl = null;
    if (StringUtils.isNotBlank(accessControl)) {
      try {
        acl = AccessControlParser.parseAcl(accessControl);
      } catch (Exception e) {
        logger.debug("Could not parse ACL", e);
        return Response.status(BAD_REQUEST).entity("Could not parse ACL").build();
      }
    }

    try {
      DublinCoreCatalog newSeries = seriesService.updateSeries(dc);
      if (acl != null) {
        seriesService.updateAccessControl(dc.getFirst(PROPERTY_IDENTIFIER), acl, override);
      }
      if (newSeries == null) {
        logger.debug("Updated series {} ", dc.getFirst(PROPERTY_IDENTIFIER));
        return Response.status(NO_CONTENT).build();
      }
      String id = newSeries.getFirst(PROPERTY_IDENTIFIER);
      logger.debug("Created series {} ", id);
      return Response.status(CREATED)
          .header("Location", getSeriesXmlUrl(id))
          .header("Location", getSeriesJsonUrl(id))
          .entity(newSeries.toXmlString())
          .build();
    } catch (UnauthorizedException e) {
      throw e;
    } catch (Exception e) {
      logger.error("Could not add/update series", e);
    }
    return Response.serverError().build();
  }

  @POST
  @Path("/{seriesID:.+}/accesscontrol")
  @Operation(
      summary = "Update the ACL of a series",
      description = "Updates the access control list for a series"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "404", description = "No series with this identifier was found."),
      @ApiResponse(responseCode = "204", description = "The access control list has been updated."),
      @ApiResponse(responseCode = "201", description = "The access control list has been created."),
      @ApiResponse(responseCode = "401", description = "If the current user is not authorized to perform this action"),
      @ApiResponse(responseCode = "400", description = "The required path or form params were missing in the request."),
      @ApiResponse(responseCode = "500", description = "The access control list could not be updated.")
  })
  public Response updateAccessControl(
      @Parameter(description = "The series identifier", required = true)
      @PathParam("seriesID") String seriesID,
      @Parameter(
          description = "The access control list for the series",
          required = true,
          schema = @Schema(example = SAMPLE_ACCESS_CONTROL_LIST)
      )
      @FormParam("acl") String accessControl,
      @Parameter(
          description = "If true the series ACL will take precedence over any existing episode ACL",
          schema = @Schema(example = "false")
      )
      @DefaultValue("false") @FormParam("override") boolean override
  ) throws UnauthorizedException {
    if (accessControl == null) {
      logger.warn("Access control parameter is null.");
      return Response.status(BAD_REQUEST).build();
    }
    AccessControlList acl;
    try {
      acl = AccessControlParser.parseAcl(accessControl);
    } catch (Exception e) {
      logger.warn("Could not parse ACL: {}", e.getMessage());
      return Response.status(BAD_REQUEST).build();
    }
    try {
      boolean updated = seriesService.updateAccessControl(seriesID, acl, override);
      if (updated) {
        return Response.status(NO_CONTENT).build();
      }
      return Response.status(CREATED).build();
    } catch (NotFoundException e) {
      return Response.status(NOT_FOUND).build();
    } catch (SeriesException e) {
      logger.warn("Could not update ACL for {}: {}", seriesID, e.getMessage());
    }
    throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
  }

  @DELETE
  @Path("/{seriesID:.+}")
  @Operation(
      summary = "Delete a series",
      description = "Delete a series"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "404", description = "No series with this identifier was found."),
      @ApiResponse(responseCode = "401", description = "If the current user is not authorized to perform this action"),
      @ApiResponse(responseCode = "204", description = "The series was deleted."),
      @ApiResponse(responseCode = "500", description = "The series could not be deleted.")
  })
  public Response deleteSeries(
      @Parameter(description = "The series identifier", required = true)
      @PathParam("seriesID") String seriesID
  ) throws UnauthorizedException {
    try {
      this.seriesService.deleteSeries(seriesID);
      return Response.ok().build();
    } catch (NotFoundException e) {
      return Response.status(Response.Status.NOT_FOUND).build();
    } catch (SeriesException se) {
      logger.warn("Could not delete series {}: {}", seriesID, se.getMessage());
    }
    throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
  }

  @GET
  @Produces(MediaType.TEXT_PLAIN)
  @Path("/count")
  @Operation(
      summary = "Get the number of series",
      description = "Returns the number of series"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The number of series")
  })
  public Response getCount() throws UnauthorizedException {
    try {
      int count = seriesService.getSeriesCount();
      return Response.ok(count).build();
    } catch (SeriesException se) {
      logger.warn("Could not count series: {}", se.getMessage());
      throw new WebApplicationException(se);
    }
  }

  @SuppressWarnings("unchecked")
  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("{id}/properties.json")
  @Operation(
      summary = "Get the properties of a series",
      description = "Returns the series properties"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The access control list."),
      @ApiResponse(responseCode = "401", description = "If the current user is not authorized to perform this action"),
      @ApiResponse(responseCode = "500", description = "The properties could not be retrieved.")
  })
  public Response getSeriesPropertiesAsJson(
      @Parameter(description = "ID of series", required = true)
      @PathParam("id") String seriesId
  )
          throws UnauthorizedException, NotFoundException {
    if (StringUtils.isBlank(seriesId)) {
      logger.warn("Series id parameter is blank '{}'.", seriesId);
      return Response.status(BAD_REQUEST).build();
    }
    try {
      Map<String, String> properties = seriesService.getSeriesProperties(seriesId);
      JsonArray jsonProperties = new JsonArray();
      for (String name : properties.keySet()) {
        JsonObject property = new JsonObject();
        property.addProperty(name, properties.get(name));
        jsonProperties.add(property);
      }
      return Response.ok(jsonProperties.toString()).build();
    } catch (UnauthorizedException e) {
      throw e;
    } catch (NotFoundException e) {
      throw e;
    } catch (Exception e) {
      logger.warn("Could not perform search query: {}", e.getMessage());
    }
    throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("{seriesId}/property/{propertyName}.json")
  @Operation(
      summary = "Get a property of a series",
      description = "Returns a series property value"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The access control list."),
      @ApiResponse(responseCode = "401", description = "If the current user is not authorized to perform this action"),
      @ApiResponse(responseCode = "500", description = "The property could not be retrieved.")
  })
  public Response getSeriesProperty(
      @Parameter(description = "ID of series", required = true)
      @PathParam("seriesId") String seriesId,
      @Parameter(description = "Name of series property", required = true)
      @PathParam("propertyName") String propertyName
  ) throws UnauthorizedException, NotFoundException {
    if (StringUtils.isBlank(seriesId)) {
      logger.warn("Series id parameter is blank '{}'.", seriesId);
      return Response.status(BAD_REQUEST).build();
    }
    if (StringUtils.isBlank(propertyName)) {
      logger.warn("Series property name parameter is blank '{}'.", propertyName);
      return Response.status(BAD_REQUEST).build();
    }
    try {
      String propertyValue = seriesService.getSeriesProperty(seriesId, propertyName);
      return Response.ok(propertyValue).build();
    } catch (UnauthorizedException e) {
      throw e;
    } catch (NotFoundException e) {
      throw e;
    } catch (Exception e) {
      logger.warn("Could not perform search query", e);
    }
    throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
  }

  @POST
  @Path("/{seriesId}/property")
  @Operation(
      summary = "Update a property of a series",
      description = "Updates a series property"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "404", description = "No series with this identifier was found."),
      @ApiResponse(responseCode = "204", description = "The access control list has been updated."),
      @ApiResponse(responseCode = "401", description = "If the current user is not authorized to perform this action"),
      @ApiResponse(responseCode = "400", description = "The required path or form params were missing in the request."),
      @ApiResponse(responseCode = "500", description = "The property could not be updated.")
  })
  public Response updateSeriesProperty(
      @Parameter(description = "The series identifier", required = true)
      @PathParam("seriesId") String seriesId,
      @Parameter(description = "The property's name", required = true)
      @FormParam("name") String name,
      @Parameter(description = "The property's value", required = true)
      @FormParam("value") String value
  ) throws UnauthorizedException {
    if (StringUtils.isBlank(seriesId)) {
      logger.warn("Series id parameter is blank '{}'.", seriesId);
      return Response.status(BAD_REQUEST).build();
    }
    if (StringUtils.isBlank(name)) {
      logger.warn("Name parameter is blank '{}'.", name);
      return Response.status(BAD_REQUEST).build();
    }
    if (StringUtils.isBlank(value)) {
      logger.warn("Series id parameter is blank '{}'.", value);
      return Response.status(BAD_REQUEST).build();
    }
    try {
      seriesService.updateSeriesProperty(seriesId, name, value);
      return Response.status(NO_CONTENT).build();
    } catch (NotFoundException e) {
      return Response.status(NOT_FOUND).build();
    } catch (SeriesException e) {
      logger.warn("Could not update series property for series {} property {}:{} :", seriesId, name, value, e);
    }
    throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
  }

  @DELETE
  @Path("{seriesId}/property/{propertyName}")
  @Operation(
      summary = "Delete a property of a series",
      description = "Deletes a series property"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "The series property has been deleted."),
      @ApiResponse(responseCode = "404", description = "The series or property has not been found."),
      @ApiResponse(responseCode = "401", description = "If the current user is not authorized to perform this action"),
      @ApiResponse(responseCode = "500", description = "The property could not be deleted.")
  })
  public Response deleteSeriesProperty(
      @Parameter(description = "ID of series", required = true)
      @PathParam("seriesId") String seriesId,
      @Parameter(description = "Name of series property", required = true)
      @PathParam("propertyName") String propertyName
  ) throws UnauthorizedException, NotFoundException {
    if (StringUtils.isBlank(seriesId)) {
      logger.warn("Series id parameter is blank '{}'.", seriesId);
      return Response.status(BAD_REQUEST).build();
    }
    if (StringUtils.isBlank(propertyName)) {
      logger.warn("Series property name parameter is blank '{}'.", propertyName);
      return Response.status(BAD_REQUEST).build();
    }
    try {
      seriesService.deleteSeriesProperty(seriesId, propertyName);
      return Response.status(NO_CONTENT).build();
    } catch (UnauthorizedException e) {
      throw e;
    } catch (NotFoundException e) {
      throw e;
    } catch (Exception e) {
      logger.warn("Could not delete series '{}' property '{}' query:", seriesId, propertyName, e);
    }
    throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
  }

  @GET
  @Path("{seriesId}/elements.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the element types of a series",
      description = "Returns all the element types of a series"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Series found"),
      @ApiResponse(responseCode = "404", description = "Series not found"),
      @ApiResponse(responseCode = "500", description = "Error while processing the request")
  })
  public Response getSeriesElements(
      @Parameter(description = "The series identifier", required = true)
      @PathParam("seriesId") String seriesId
  ) {
    try {
      Optional<Map<String, byte[]>> optSeriesElements = seriesService.getSeriesElements(seriesId);
      if (optSeriesElements.isPresent()) {
        Map<String, byte[]> seriesElements = optSeriesElements.get();
        JsonArray jsonArray = new JsonArray();
        for (String key : seriesElements.keySet()) {
          jsonArray.add(new JsonPrimitive(key));
        }
        String json = new Gson().toJson(jsonArray);
        return Response.ok(json).build();
      } else {
        return R.notFound();
      }
    } catch (SeriesException e) {
      logger.warn("Error while retrieving elements for sieres '{}'", seriesId, e);
      return R.serverError();
    }
  }

  @GET
  @Path("{seriesId}/elements/{elementType}")
  @Operation(
      summary = "Get an element of a series",
      description = "Returns the series element"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Series element found"),
      @ApiResponse(responseCode = "404", description = "Series element not found"),
      @ApiResponse(responseCode = "500", description = "Error while processing the request")
  })
  public Response getSeriesElement(
      @Parameter(description = "The series identifier", required = true)
      @PathParam("seriesId") String seriesId,
      @Parameter(
          description = "The element type. This is equal to the subtype of the media type of "
              + "this element: series/<elementtype>",
          required = true
      )
      @PathParam("elementType") String elementType
  ) {
    try {
      Optional<byte[]> data = seriesService.getSeriesElementData(seriesId, elementType);
      if (data.isPresent()) {
        return Response.ok().entity(new ByteArrayInputStream(data.get()))
                .type(SERIES_ELEMENT_CONTENT_TYPE_PREFIX + elementType).build();
      } else {
        return R.notFound();
      }
    } catch (SeriesException e) {
      logger.warn("Error while returning element '{}' of series '{}':", elementType, seriesId, e);
      return R.serverError();
    }
  }

  @PUT
  @Path("{seriesId}/extendedMetadata/{type}")
  @Operation(
      summary = "Update the extended metadata of a series",
      description = "Updates extended metadata of a series"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "Extended metadata updated"),
      @ApiResponse(responseCode = "201", description = "Extended metadata created"),
      @ApiResponse(responseCode = "500", description = "Error while processing the request")
  })
  public Response putSeriesExtendedMetadata(
      @Parameter(description = "The series identifier", required = true)
      @PathParam("seriesId") String seriesId,
      @Parameter(description = "The type of the catalog flavor", required = true)
      @PathParam("type") String type,
      @Parameter(
          description = "The catalog with extended metadata.",
          required = true,
          schema = @Schema(example = SAMPLE_DUBLIN_CORE)
      )
      @FormParam("dc") String dcString
  ) {
    try {
      DublinCoreCatalog dc = dcService.load(new ByteArrayInputStream(dcString.getBytes(StandardCharsets.UTF_8)));
      boolean elementExists = seriesService.getSeriesElementData(seriesId, type).isPresent();
      if (seriesService.updateExtendedMetadata(seriesId, type, dc)) {
        if (elementExists) {
          return R.noContent();
        } else {
          return R.created(URI.create(UrlSupport.concat(serverUrl, serviceUrl, seriesId, "elements", type)));
        }
      } else {
        return R.serverError();
      }
    } catch (IOException e) {
      logger.warn("Could not deserialize dublin core catalog", e);
      return Response.status(BAD_REQUEST).build();
    } catch (SeriesException e) {
      logger.warn("Error while updating extended metadata of series '{}'", seriesId, e);
      return R.serverError();
    }
  }


  @PUT
  @Path("{seriesId}/elements/{elementType}")
  @Operation(
      summary = "Update an element of a series",
      description = "Updates an existing series element"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "Series element updated"),
      @ApiResponse(responseCode = "201", description = "Series element created"),
      @ApiResponse(responseCode = "500", description = "Error while processing the request")
  })
  public Response putSeriesElement(
      @Context HttpServletRequest request,
      @Parameter(description = "The series identifier", required = true)
      @PathParam("seriesId") String seriesId,
      @Parameter(description = "The element type", required = true)
      @PathParam("elementType") String elementType
  ) {
    InputStream is = null;
    try {
      is = request.getInputStream();
      final byte[] data = IOUtils.toByteArray(is);
      boolean elementExists = seriesService.getSeriesElementData(seriesId, elementType).isPresent();
      if (seriesService.updateSeriesElement(seriesId, elementType, data)) {
        if (elementExists) {
          return R.noContent();
        } else {
          return R.created(URI.create(UrlSupport.concat(serverUrl, serviceUrl, seriesId, "elements", elementType)));
        }
      } else {
        return R.serverError();
      }
    } catch (IOException e) {
      logger.error("Error while trying to read from request", e);
      return R.serverError();
    } catch (SeriesException e) {
      logger.warn("Error while adding element to series '{}'", seriesId, e);
      return R.serverError();
    } finally {
      IOUtils.closeQuietly(is);
    }
  }

  @DELETE
  @Path("{seriesId}/elements/{elementType}")
  @Operation(
      summary = "Delete an element of a series",
      description = "Deletes a series element"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "Series element deleted"),
      @ApiResponse(responseCode = "404", description = "Series element not found"),
      @ApiResponse(responseCode = "500", description = "Error while processing the request")
  })
  public Response deleteSeriesElement(
      @Parameter(description = "The series identifier", required = true)
      @PathParam("seriesId") String seriesId,
      @Parameter(description = "The element type", required = true)
      @PathParam("elementType") String elementType
  ) {
    try {
      if (seriesService.deleteSeriesElement(seriesId, elementType)) {
        return R.noContent();
      } else {
        return R.notFound();
      }
    } catch (SeriesException e) {
      return R.serverError();
    }
  }

}
