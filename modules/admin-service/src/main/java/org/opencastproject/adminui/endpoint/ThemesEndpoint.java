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

package org.opencastproject.adminui.endpoint;

import static org.apache.commons.lang3.StringUtils.isNotBlank;
import static org.apache.commons.lang3.StringUtils.trimToNull;
import static org.opencastproject.index.service.util.JSONUtils.safeString;
import static org.opencastproject.index.service.util.RestUtils.notFound;
import static org.opencastproject.index.service.util.RestUtils.okJson;
import static org.opencastproject.index.service.util.RestUtils.okJsonList;

import org.opencastproject.index.service.util.RestUtils;
import org.opencastproject.opensearch.api.SearchIndexException;
import org.opencastproject.opensearch.api.SearchResult;
import org.opencastproject.opensearch.api.SearchResultItem;
import org.opencastproject.opensearch.index.OpenSearchIndex;
import org.opencastproject.opensearch.index.objects.series.Series;
import org.opencastproject.opensearch.index.objects.series.SeriesSearchQuery;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.security.api.UnauthorizedException;
import org.opencastproject.security.api.User;
import org.opencastproject.series.api.SeriesException;
import org.opencastproject.series.api.SeriesService;
import org.opencastproject.staticfiles.api.StaticFileService;
import org.opencastproject.staticfiles.endpoint.StaticFileRestService;
import org.opencastproject.themes.Theme;
import org.opencastproject.themes.ThemesServiceDatabase;
import org.opencastproject.themes.list.ThemesListQuery;
import org.opencastproject.themes.persistence.ThemesServiceDatabaseException;
import org.opencastproject.util.DateTimeSupport;
import org.opencastproject.util.NotFoundException;
import org.opencastproject.util.RestUtil;
import org.opencastproject.util.RestUtil.R;
import org.opencastproject.util.requests.SortCriterion;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import javax.ws.rs.DELETE;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

@Path("/admin-ng/themes")
@Tag(
    name = "Admin UI - Themes",
    description = "Provides operations for the themes"
)
@Component(
    immediate = true,
    service = ThemesEndpoint.class,
    property = {
        "service.description=Admin UI - Themes Endpoint",
        "opencast.service.type=org.opencastproject.adminui.ThemesEndpoint",
        "opencast.service.path=/admin-ng/themes",
    }
)
@JaxrsResource
public class ThemesEndpoint {

  /** The logging facility */
  private static final Logger logger = LoggerFactory.getLogger(ThemesEndpoint.class);

  /** The themes service database */
  private ThemesServiceDatabase themesServiceDatabase;

  /** The security service */
  private SecurityService securityService;

  /** The admin UI search index */
  private OpenSearchIndex searchIndex;

  /** The series service */
  private SeriesService seriesService;

  /** The static file service */
  private StaticFileService staticFileService;

  /** The static file REST service */
  private StaticFileRestService staticFileRestService;

  /** OSGi callback for the themes service database. */
  @Reference
  public void setThemesServiceDatabase(ThemesServiceDatabase themesServiceDatabase) {
    this.themesServiceDatabase = themesServiceDatabase;
  }

  /** OSGi callback for the security service. */
  @Reference
  public void setSecurityService(SecurityService securityService) {
    this.securityService = securityService;
  }

  /** OSGi DI. */
  @Reference
  public void setIndex(OpenSearchIndex index) {
    this.searchIndex = index;
  }

  /** OSGi DI. */
  @Reference
  public void setSeriesService(SeriesService seriesService) {
    this.seriesService = seriesService;
  }

  /** OSGi DI. */
  @Reference
  public void setStaticFileService(StaticFileService staticFileService) {
    this.staticFileService = staticFileService;
  }

  /** OSGi DI. */
  @Reference
  public void setStaticFileRestService(StaticFileRestService staticFileRestService) {
    this.staticFileRestService = staticFileRestService;
  }

  @Activate
  public void activate(BundleContext bundleContext) {
    logger.info("Activate themes endpoint");
  }

  @GET
  @Produces({ MediaType.APPLICATION_JSON })
  @Path("themes.json")
  @Operation(
      summary = "Get themes",
      description = "Return all of the known themes on the system"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "A JSON representation of the themes")
  })
  public Response getThemes(
      @Parameter(
          description = "The filter used for the query. They "
              + "should be formated like that: 'filter1:value1,filter2:value2'"
      )
      @QueryParam("filter") String filter,
      @Parameter(description = "The maximum number of items to return per page.", example = "0")
      @QueryParam("limit") int limit,
      @Parameter(description = "The page number.", example = "0")
      @QueryParam("offset") int offset,
      @Parameter(
          description = "The sort order. May include any of the "
              + "following: NAME, CREATOR.  Add '_DESC' to reverse the sort order (e.g. CREATOR_DESC)."
      )
      @QueryParam("sort") String sort
  ) {
    Optional<Integer> optLimit = Optional.ofNullable(limit);
    Optional<Integer> optOffset = Optional.ofNullable(offset);
    Optional<String> optSort = Optional.ofNullable(trimToNull(sort));

    Map<String, String> filters = RestUtils.parseFilter(filter);

    ArrayList<SortCriterion> sortCriteria;
    if (optSort.isPresent()) {
      sortCriteria = RestUtils.parseSortQueryParameter(optSort.get());
    } else {
      sortCriteria = new ArrayList<>();
    }
    Optional<String> optCreatorFilter = Optional.ofNullable(filters.get(ThemesListQuery.FILTER_CREATOR_NAME));
    Optional<String> optTextFilter = Optional.ofNullable(filters.get(ThemesListQuery.FILTER_TEXT_NAME));

    List<Theme> results = null;
    int total;
    try {
      results = themesServiceDatabase.findThemes(
          optLimit,
          optOffset,
          sortCriteria,
          optCreatorFilter,
          optTextFilter
      );
      total = themesServiceDatabase.countThemes();
    } catch (Exception e) {
      logger.error("Could not get themes from the database:", e);
      return RestUtil.R.serverError();
    }


    List<JsonObject> themesJSON = new ArrayList<>();
    for (Theme theme : results) {
      themesJSON.add(themeToJSON(theme, false));
    }

    return okJsonList(
        themesJSON,
        Optional.ofNullable(offset).orElse(0),
        Optional.ofNullable(limit).orElse(0),
        total
    );
  }

  @GET
  @Path("{themeId}.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get a theme",
      description = "Returns the theme by the given id as JSON"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returns the theme as JSON"),
      @ApiResponse(responseCode = "404", description = "No theme with this identifier was found.")
  })
  public Response getThemeResponse(
      @Parameter(description = "The theme id", required = true)
      @PathParam("themeId") long id
  ) {
    try {
      Theme theme = themesServiceDatabase.getTheme(id);

      return okJson(themeToJSON(theme, true));
    } catch (ThemesServiceDatabaseException e) {
      return RestUtil.R.serverError();
    } catch (NotFoundException e) {
      return notFound("Cannot find a theme with id '%s'", id);
    }
  }

  @GET
  @Path("{themeId}/usage.json")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Get the usage of a theme",
      description = "Returns the theme usage by the given id as JSON"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Returns the theme usage as JSON"),
      @ApiResponse(responseCode = "404", description = "Theme with the given id does not exist")
  })
  public Response getThemeUsage(
      @Parameter(description = "The theme id", required = true)
      @PathParam("themeId") long themeId
  ) {
    try {
      themesServiceDatabase.getTheme(themeId);

      SeriesSearchQuery query = new SeriesSearchQuery(securityService.getOrganization().getId(),
              securityService.getUser()).withTheme(themeId);
      SearchResult<Series> results = null;
      try {
        results = searchIndex.getByQuery(query);
      } catch (SearchIndexException e) {
        if (e.isBadRequest()) {
          logger.warn("The admin UI Search Index rejected the query for series with theme '{}': {}", themeId,
                  e.getMessage());
          return RestUtil.R.badRequest(e.getMessage());
        }
        logger.error("The admin UI Search Index was not able to get the series with theme '{}':", themeId,
                e);
        return RestUtil.R.serverError();
      }
      JsonArray seriesValues = new JsonArray();
      for (SearchResultItem<Series> item : results.getItems()) {
        Series series = item.getSource();
        JsonObject seriesJson = new JsonObject();
        seriesJson.addProperty("id", series.getIdentifier());
        seriesJson.addProperty("title", series.getTitle());
        seriesValues.add(seriesJson);
      }
      JsonObject responseJson = new JsonObject();
      responseJson.add("series", seriesValues);

      return okJson(responseJson);
    } catch (ThemesServiceDatabaseException e) {
      return RestUtil.R.serverError();
    } catch (NotFoundException e) {
      return notFound("Cannot find a theme with id {}", themeId);
    }
  }

  @POST
  @Path("")
  @Operation(
      summary = "Create a theme",
      description = "Add a theme"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Theme created"),
      @ApiResponse(responseCode = "400", description = "The theme references a non-existing file")
  })
  public Response createTheme(
      @Parameter(description = "Whether the theme is default", required = true)
      @FormParam("default") boolean isDefault,
      @Parameter(description = "The theme name", required = true)
      @FormParam("name") String name,
      @Parameter(description = "The theme description")
      @FormParam("description") String description,
      @Parameter(description = "Whether the theme bumper is active")
      @FormParam("bumperActive") Boolean bumperActive,
      @Parameter(description = "Whether the theme trailer is active")
      @FormParam("trailerActive") Boolean trailerActive,
      @Parameter(description = "Whether the theme title slide is active")
      @FormParam("titleSlideActive") Boolean titleSlideActive,
      @Parameter(description = "Whether the theme license slide is active")
      @FormParam("licenseSlideActive") Boolean licenseSlideActive,
      @Parameter(description = "Whether the theme watermark is active")
      @FormParam("watermarkActive") Boolean watermarkActive,
      @Parameter(description = "The theme bumper file")
      @FormParam("bumperFile") String bumperFile,
      @Parameter(description = "The theme trailer file")
      @FormParam("trailerFile") String trailerFile,
      @Parameter(description = "The theme watermark file")
      @FormParam("watermarkFile") String watermarkFile,
      @Parameter(description = "The theme title slide background file")
      @FormParam("titleSlideBackground") String titleSlideBackground,
      @Parameter(description = "The theme license slide background file")
      @FormParam("licenseSlideBackground") String licenseSlideBackground,
      @Parameter(description = "The theme title slide metadata")
      @FormParam("titleSlideMetadata") String titleSlideMetadata,
      @Parameter(description = "The theme license slide description")
      @FormParam("licenseSlideDescription") String licenseSlideDescription,
      @Parameter(description = "The theme watermark position")
      @FormParam("watermarkPosition") String watermarkPosition
  ) {
    User creator = securityService.getUser();

    Theme theme = new Theme(Optional.<Long> empty(), new Date(), isDefault, creator, name,
            StringUtils.trimToNull(description), BooleanUtils.toBoolean(bumperActive),
            StringUtils.trimToNull(bumperFile), BooleanUtils.toBoolean(trailerActive),
            StringUtils.trimToNull(trailerFile), BooleanUtils.toBoolean(titleSlideActive),
            StringUtils.trimToNull(titleSlideMetadata), StringUtils.trimToNull(titleSlideBackground),
            BooleanUtils.toBoolean(licenseSlideActive), StringUtils.trimToNull(licenseSlideBackground),
            StringUtils.trimToNull(licenseSlideDescription), BooleanUtils.toBoolean(watermarkActive),
            StringUtils.trimToNull(watermarkFile), StringUtils.trimToNull(watermarkPosition));

    try {
      persistReferencedFiles(theme);
    } catch (NotFoundException e) {
      logger.warn("A file that is referenced in theme '{}' was not found: {}", theme, e.getMessage());
      return R.badRequest("Referenced non-existing file");
    } catch (IOException e) {
      logger.warn("Error while persisting file: {}", e.getMessage());
      return R.serverError();
    }

    try {
      Theme createdTheme = themesServiceDatabase.updateTheme(theme);
      return RestUtils.okJson(themeToJSON(createdTheme,false));
    } catch (ThemesServiceDatabaseException e) {
      logger.error("Unable to create a theme");
      return RestUtil.R.serverError();
    }
  }

  @PUT
  @Path("{themeId}")
  @Operation(
      summary = "Update a theme",
      description = "Updates a theme"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Theme updated"),
      @ApiResponse(responseCode = "404", description = "If the theme has not been found.")
  })
  public Response updateTheme(
      @Parameter(description = "The theme identifier", required = true)
      @PathParam("themeId") long themeId,
      @Parameter(description = "Whether the theme is default")
      @FormParam("default") Boolean isDefault,
      @Parameter(description = "The theme name")
      @FormParam("name") String name,
      @Parameter(description = "The theme description")
      @FormParam("description") String description,
      @Parameter(description = "Whether the theme bumper is active")
      @FormParam("bumperActive") Boolean bumperActive,
      @Parameter(description = "Whether the theme trailer is active")
      @FormParam("trailerActive") Boolean trailerActive,
      @Parameter(description = "Whether the theme title slide is active")
      @FormParam("titleSlideActive") Boolean titleSlideActive,
      @Parameter(description = "Whether the theme license slide is active")
      @FormParam("licenseSlideActive") Boolean licenseSlideActive,
      @Parameter(description = "Whether the theme watermark is active")
      @FormParam("watermarkActive") Boolean watermarkActive,
      @Parameter(description = "The theme bumper file")
      @FormParam("bumperFile") String bumperFile,
      @Parameter(description = "The theme trailer file")
      @FormParam("trailerFile") String trailerFile,
      @Parameter(description = "The theme watermark file")
      @FormParam("watermarkFile") String watermarkFile,
      @Parameter(description = "The theme title slide background file")
      @FormParam("titleSlideBackground") String titleSlideBackground,
      @Parameter(description = "The theme license slide background file")
      @FormParam("licenseSlideBackground") String licenseSlideBackground,
      @Parameter(description = "The theme title slide metadata")
      @FormParam("titleSlideMetadata") String titleSlideMetadata,
      @Parameter(description = "The theme license slide description")
      @FormParam("licenseSlideDescription") String licenseSlideDescription,
      @Parameter(description = "The theme watermark position")
      @FormParam("watermarkPosition") String watermarkPosition
  ) throws NotFoundException {
    try {
      Theme origTheme = themesServiceDatabase.getTheme(themeId);

      if (isDefault == null) {
        isDefault = origTheme.isDefault();
      }
      if (StringUtils.isBlank(name)) {
        name = origTheme.getName();
      }
      if (StringUtils.isEmpty(description)) {
        description = origTheme.getDescription();
      }
      if (bumperActive == null) {
        bumperActive = origTheme.isBumperActive();
      }
      if (StringUtils.isEmpty(bumperFile)) {
        bumperFile = origTheme.getBumperFile();
      }
      if (trailerActive == null) {
        trailerActive = origTheme.isTrailerActive();
      }
      if (StringUtils.isEmpty(trailerFile)) {
        trailerFile = origTheme.getTrailerFile();
      }
      if (titleSlideActive == null) {
        titleSlideActive = origTheme.isTitleSlideActive();
      }
      if (StringUtils.isEmpty(titleSlideMetadata)) {
        titleSlideMetadata = origTheme.getTitleSlideMetadata();
      }
      if (StringUtils.isEmpty(titleSlideBackground)) {
        titleSlideBackground = origTheme.getTitleSlideBackground();
      }
      if (licenseSlideActive == null) {
        licenseSlideActive = origTheme.isLicenseSlideActive();
      }
      if (StringUtils.isEmpty(licenseSlideBackground)) {
        licenseSlideBackground = origTheme.getLicenseSlideBackground();
      }
      if (StringUtils.isEmpty(licenseSlideDescription)) {
        licenseSlideDescription = origTheme.getLicenseSlideDescription();
      }
      if (watermarkActive == null) {
        watermarkActive = origTheme.isWatermarkActive();
      }
      if (StringUtils.isEmpty(watermarkFile)) {
        watermarkFile = origTheme.getWatermarkFile();
      }
      if (StringUtils.isEmpty(watermarkPosition)) {
        watermarkPosition = origTheme.getWatermarkPosition();
      }

      Theme theme = new Theme(origTheme.getId(), origTheme.getCreationDate(), isDefault, origTheme.getCreator(), name,
          StringUtils.trimToNull(description), BooleanUtils.toBoolean(bumperActive),
          StringUtils.trimToNull(bumperFile), BooleanUtils.toBoolean(trailerActive),
          StringUtils.trimToNull(trailerFile), BooleanUtils.toBoolean(titleSlideActive),
          StringUtils.trimToNull(titleSlideMetadata), StringUtils.trimToNull(titleSlideBackground),
          BooleanUtils.toBoolean(licenseSlideActive), StringUtils.trimToNull(licenseSlideBackground),
          StringUtils.trimToNull(licenseSlideDescription), BooleanUtils.toBoolean(watermarkActive),
          StringUtils.trimToNull(watermarkFile), StringUtils.trimToNull(watermarkPosition));

      try {
        updateReferencedFiles(origTheme, theme);
      } catch (IOException e) {
        logger.warn("Error while persisting file: {}", e.getMessage());
        return R.serverError();
      } catch (NotFoundException e) {
        logger.warn("A file that is referenced in theme '{}' was not found: {}", theme, e.getMessage());
        return R.badRequest("Referenced non-existing file");
      }

      Theme updatedTheme = themesServiceDatabase.updateTheme(theme);
      return RestUtils.okJson(themeToJSON(updatedTheme, false));
    } catch (ThemesServiceDatabaseException e) {
      logger.error("Unable to update theme {}", themeId, e);
      return RestUtil.R.serverError();
    }
  }

  @DELETE
  @Path("{themeId}")
  @Operation(
      summary = "Delete a theme",
      description = "Deletes a theme"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "404", description = "If the theme has not been found."),
      @ApiResponse(responseCode = "204", description = "The method does not return any content"),
      @ApiResponse(
          responseCode = "401",
          description = "If the current user is not authorized to perform this action"
      )
  })
  public Response deleteTheme(
      @Parameter(description = "The theme identifier", required = true)
      @PathParam("themeId") long themeId
  ) throws NotFoundException, UnauthorizedException {
    try {
      Theme theme = themesServiceDatabase.getTheme(themeId);
      try {
        deleteReferencedFiles(theme);
      } catch (IOException e) {
        logger.warn("Error while deleting referenced file: {}", e.getMessage());
        return R.serverError();
      }

      themesServiceDatabase.deleteTheme(themeId);
      deleteThemeOnSeries(themeId);

      return RestUtil.R.noContent();
    } catch (NotFoundException e) {
      logger.warn("Unable to find a theme with id " + themeId);
      throw e;
    } catch (ThemesServiceDatabaseException e) {
      logger.error("Error getting theme {} during delete operation because:", themeId,
              e);
      return RestUtil.R.serverError();
    }
  }

  /**
   * Deletes all related series theme entries
   *
   * @param themeId
   *          the theme id
   */
  private void deleteThemeOnSeries(long themeId) throws UnauthorizedException {
    SeriesSearchQuery query = new SeriesSearchQuery(securityService.getOrganization().getId(),
            securityService.getUser()).withTheme(themeId);
    SearchResult<Series> results = null;
    try {
      results = searchIndex.getByQuery(query);
    } catch (SearchIndexException e) {
      if (e.isBadRequest()) {
        logger.warn("The admin UI Search Index rejected the query for series with theme '{}': {}", themeId,
                e.getMessage());
        throw new WebApplicationException(Status.BAD_REQUEST);
      }
      logger.error("The admin UI Search Index was not able to get the series with theme '{}':", themeId, e);
      throw new WebApplicationException(e, Status.INTERNAL_SERVER_ERROR);
    }
    for (SearchResultItem<Series> item : results.getItems()) {
      String seriesId = item.getSource().getIdentifier();
      try {
        seriesService.deleteSeriesProperty(seriesId, SeriesEndpoint.THEME_KEY);
      } catch (NotFoundException e) {
        logger.warn("Theme {} already deleted on series {}", themeId, seriesId);
      } catch (SeriesException e) {
        logger.error("Unable to remove theme from series {}", seriesId, e);
        throw new WebApplicationException(e, Status.INTERNAL_SERVER_ERROR);
      }
    }
  }

  private void extendStaticFileInfo(String fieldName, String staticFileId, JsonObject json) {
    if (StringUtils.isNotBlank(staticFileId)) {
      try {
        String fileName = staticFileService.getFileName(staticFileId);
        String fileUrl = staticFileRestService.getStaticFileURL(staticFileId).toString();

        json.addProperty(fieldName + "Name", fileName);
        json.addProperty(fieldName + "Url", safeString(fileUrl));
      } catch (IllegalStateException | NotFoundException e) {
        logger.error("Error retrieving static file '{}'", staticFileId, e);
      }
    }
  }

  /**
   * Returns the JSON representation of this theme.
   *
   * @param theme
   *          the theme
   * @param editResponse
   *          whether the returning representation should contain edit information
   * @return the JSON representation of this theme.
   */
  private JsonObject themeToJSON(Theme theme, boolean editResponse) {
    String creator = StringUtils.isNotBlank(theme.getCreator().getName())
        ? theme.getCreator().getName()
        : theme.getCreator().getUsername();

    JsonObject json = new JsonObject();

    json.addProperty("id",  theme.getId().orElse(-1L));
    json.addProperty("creationDate", DateTimeSupport.toUTC(theme.getCreationDate().getTime()));
    json.addProperty("default", theme.isDefault());
    json.addProperty("name", theme.getName());
    json.addProperty("creator", creator);
    json.addProperty("description", safeString(theme.getDescription()));
    json.addProperty("bumperActive", theme.isBumperActive());
    json.addProperty("bumperFile", safeString(theme.getBumperFile()));
    json.addProperty("trailerActive", theme.isTrailerActive());
    json.addProperty("trailerFile", safeString(theme.getTrailerFile()));
    json.addProperty("titleSlideActive", theme.isTitleSlideActive());
    json.addProperty("titleSlideMetadata", safeString(theme.getTitleSlideMetadata()));
    json.addProperty("titleSlideBackground", safeString(theme.getTitleSlideBackground()));
    json.addProperty("licenseSlideActive", theme.isLicenseSlideActive());
    json.addProperty("licenseSlideDescription", safeString(theme.getLicenseSlideDescription()));
    json.addProperty("licenseSlideBackground", safeString(theme.getLicenseSlideBackground()));
    json.addProperty("watermarkActive", theme.isWatermarkActive());
    json.addProperty("watermarkFile", theme.getWatermarkFile() != null ? theme.getWatermarkFile() : "");
    json.addProperty("watermarkPosition", theme.getWatermarkPosition() != null ? theme.getWatermarkPosition() : "");

    if (editResponse) {
      extendStaticFileInfo("bumperFile", theme.getBumperFile(), json);
      extendStaticFileInfo("trailerFile", theme.getTrailerFile(), json);
      extendStaticFileInfo("titleSlideBackground", theme.getTitleSlideBackground(), json);
      extendStaticFileInfo("licenseSlideBackground", theme.getLicenseSlideBackground(), json);
      extendStaticFileInfo("watermarkFile", theme.getWatermarkFile(), json);
    }

    return json;
  }

  /**
   * Persist all files that are referenced in the theme.
   *
   * @param theme
   *          The theme
   * @throws NotFoundException
   *           If a referenced file is not found.
   * @throws IOException
   *           If there was an error while persisting the file.
   */
  private void persistReferencedFiles(Theme theme) throws NotFoundException, IOException {
    if (isNotBlank(theme.getBumperFile())) {
      staticFileService.persistFile(theme.getBumperFile());
    }
    if (isNotBlank(theme.getLicenseSlideBackground())) {
      staticFileService.persistFile(theme.getLicenseSlideBackground());
    }
    if (isNotBlank(theme.getTitleSlideBackground())) {
      staticFileService.persistFile(theme.getTitleSlideBackground());
    }
    if (isNotBlank(theme.getTrailerFile())) {
      staticFileService.persistFile(theme.getTrailerFile());
    }
    if (isNotBlank(theme.getWatermarkFile())) {
      staticFileService.persistFile(theme.getWatermarkFile());
    }
  }

  /**
   * Delete all files that are referenced in the theme.
   *
   * @param theme
   *          The theme
   * @throws NotFoundException
   *           If a referenced file is not found.
   * @throws IOException
   *           If there was an error while persisting the file.
   */
  private void deleteReferencedFiles(Theme theme) throws NotFoundException, IOException {
    if (isNotBlank(theme.getBumperFile())) {
      staticFileService.deleteFile(theme.getBumperFile());
    }
    if (isNotBlank(theme.getLicenseSlideBackground())) {
      staticFileService.deleteFile(theme.getLicenseSlideBackground());
    }
    if (isNotBlank(theme.getTitleSlideBackground())) {
      staticFileService.deleteFile(theme.getTitleSlideBackground());
    }
    if (isNotBlank(theme.getTrailerFile())) {
      staticFileService.deleteFile(theme.getTrailerFile());
    }
    if (isNotBlank(theme.getWatermarkFile())) {
      staticFileService.deleteFile(theme.getWatermarkFile());
    }
  }

  /**
   * Update all files that have changed between {@code original} and {@code updated}.
   *
   * @param original
   *          The original theme
   * @param updated
   *          The updated theme
   * @throws NotFoundException
   *           If one of the referenced files could not be found.
   * @throws IOException
   *           If there was an error while updating the referenced files.
   */
  private void updateReferencedFiles(Theme original, Theme updated) throws NotFoundException, IOException {
    updateReferencedFile(original.getBumperFile(), updated.getBumperFile());
    updateReferencedFile(original.getLicenseSlideBackground(), updated.getLicenseSlideBackground());
    updateReferencedFile(original.getTitleSlideBackground(), updated.getTitleSlideBackground());
    updateReferencedFile(original.getTrailerFile(), updated.getTrailerFile());
    updateReferencedFile(original.getWatermarkFile(), updated.getWatermarkFile());
  }

  /**
   * If the file resource has changed between {@code original} and {@code updated}, the original file is deleted and the
   * updated one persisted.
   *
   * @param original
   *          The UUID of the original file
   * @param updated
   *          The UUID of the updated file
   * @throws NotFoundException
   *           If the file could not be found
   * @throws IOException
   *           If there was an error while persisting or deleting one of the files.
   */
  private void updateReferencedFile(String original, String updated) throws NotFoundException, IOException {
    if (!Objects.equals(original, updated)) {
      if (isNotBlank(original)) {
        staticFileService.deleteFile(original);
      }
      if (isNotBlank(updated)) {
        staticFileService.persistFile(updated);
      }
    }
  }

}
