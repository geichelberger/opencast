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

package org.opencastproject.smil.endpoint;

import org.opencastproject.mediapackage.MediaPackage;
import org.opencastproject.mediapackage.MediaPackageElementParser;
import org.opencastproject.mediapackage.MediaPackageException;
import org.opencastproject.mediapackage.MediaPackageParser;
import org.opencastproject.mediapackage.Track;
import org.opencastproject.smil.api.SmilException;
import org.opencastproject.smil.api.SmilResponse;
import org.opencastproject.smil.api.SmilService;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.jaxrs.whiteboard.propertytypes.JaxrsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import javax.servlet.http.HttpServletResponse;
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
 * Implement {@link SmilService} as REST Endpoint.
 */
@Path("/smil")
@Tag(
    name = "SmilService Rest Endpoint",
    description = "SmilRestService provides other services to create and modify Smil objects."
)
@Component(
    property = {
        "service.description=Smil Service REST Endpoint",
        "opencast.service.type=org.opencastproject.smil",
        "opencast.service.path=/smil"
    },
    immediate = true,
    service = { SmilServiceRest.class }
)
@JaxrsResource
public class SmilServiceRest {

  /**
   * Logger
   */
  private static final Logger logger = LoggerFactory.getLogger(SmilServiceRest.class);

  /**
   * SmilService to interact with
   */
  private SmilService smilService;

  @POST
  @Path("create")
  @Produces({MediaType.APPLICATION_XML, MediaType.TEXT_XML})
  @Operation(
      summary = "Create a SMIL",
      description = "Create new SMIL. Add some MediaPackage metadata."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Create new SMIL successful"),
      @ApiResponse(responseCode = "400", description = "Given mediaPackage is not valid")
  })
  public Response createNewSmil(
      @Parameter(description = "MediaPackage for metadata.")
      @FormParam("mediaPackage") String mediaPackage
  ) {
    SmilResponse smilResponse = null;
    try {
      if (mediaPackage != null && !mediaPackage.isEmpty()) {
        MediaPackage mp = MediaPackageParser.getFromXml(mediaPackage);
        smilResponse = smilService.createNewSmil(mp);
      } else {
        smilResponse = smilService.createNewSmil();
      }

      return Response.ok(smilResponse).build();
    } catch (MediaPackageException ex) {
      logger.info(ex.getMessage(), ex);
      return Response.status(HttpServletResponse.SC_BAD_REQUEST).entity("MediaPackage not valid.").build();
    }
  }

  @POST
  @Path("addPar")
  @Produces({MediaType.APPLICATION_XML, MediaType.TEXT_XML})
  @Operation(
      summary = "Add a parallel element to a SMIL",
      description = "Add a parallel element to SMIL (into SMIL body or an element with given parentId)."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Add par to SMIL successful."),
      @ApiResponse(
          responseCode = "400",
          description = "SMIL document not valid or it doesn't contain an element with given parentId"
      )
  })
  public Response addParallel(
      @Parameter(description = "SMIL document where to add a par-element.", required = true)
      @FormParam("smil") String smil,
      @Parameter(description = "An element Id, where to add new parallel.")
      @FormParam("parentId") String parentId
  ) {
    SmilResponse smilResponse = null;
    try {
      smilResponse = smilService.fromXml(smil);
    } catch (SmilException ex) {
      return Response.status(HttpServletResponse.SC_BAD_REQUEST).entity("SMIL document invalid.").build();
    }

    try {
      if (parentId != null && !parentId.isEmpty()) {
        smilResponse = smilService.addParallel(smilResponse.getSmil(), parentId);
      } else {
        smilResponse = smilService.addParallel(smilResponse.getSmil());
      }
      return Response.ok(smilResponse).build();
    } catch (SmilException ex) {
      logger.info(ex.getMessage(), ex);
      return Response.status(HttpServletResponse.SC_BAD_REQUEST)
          .entity("SMIL document doesn't contain an element with given parentId.")
          .build();
    }
  }

  @POST
  @Path("addSeq")
  @Produces({MediaType.APPLICATION_XML, MediaType.TEXT_XML})
  @Operation(
      summary = "Add a sequence element to a SMIL",
      description = "Add a sequence element to SMIL (into SMIL body or an element with given parentId)."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Add seq to SMIL successful"),
      @ApiResponse(
          responseCode = "400",
          description = "SMIL document not valid or it doesn't contain an element with given parentId"
      )
  })
  public Response addSequence(
      @Parameter(description = "SMIL document where to add a seq-element.", required = true)
      @FormParam("smil") String smil,
      @Parameter(description = "An element Id, where to add new sequence.")
      @FormParam("parentId") String parentId
  ) {
    SmilResponse smilResponse = null;
    try {
      smilResponse = smilService.fromXml(smil);
    } catch (SmilException ex) {
      logger.info(ex.getMessage(), ex);
      return Response.status(HttpServletResponse.SC_BAD_REQUEST).entity("SMIL document invalid.").build();
    }

    try {
      if (parentId != null && !parentId.isEmpty()) {
        smilResponse = smilService.addSequence(smilResponse.getSmil(), parentId);
      } else {
        smilResponse = smilService.addSequence(smilResponse.getSmil());
      }
      return Response.ok(smilResponse).build();
    } catch (SmilException ex) {
      logger.info(ex.getMessage(), ex);
      return Response.status(HttpServletResponse.SC_BAD_REQUEST)
          .entity("SMIL document doesn't contain an element with given parentId.")
          .build();
    }
  }

  @POST
  @Path("addClip")
  @Produces({MediaType.APPLICATION_XML, MediaType.TEXT_XML})
  @Operation(
      summary = "Add a media element to a SMIL",
      description = "Add new media element based on given Track information and start / duration parameters. "
          + "ParentId specifies where to put the new media element."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Add media element to SMIL successful."),
      @ApiResponse(
          responseCode = "400",
          description = "SMIL document or track not valid, the SMIL document doesn't contain an element with given "
              + "parentId, or start plus duration is bigger than the track length"
      )
  })
  public Response addClip(
      @Parameter(description = "SMIL document where to add new media element.", required = true)
      @FormParam("smil") String smil,
      @Parameter(description = "An element Id, where to add new media.")
      @FormParam("parentId") String parentId,
      @Parameter(
          description = "Track (MediaPackageElement) to add as media element. "
              + "Some information like Track source and flavor will be stored in ParamGroup (in SMIL Head) "
              + "and referenced by paramGroup media element attribute.",
          required = true
      )
      @FormParam("track") String track,
      @Parameter(description = "Track start position in milliseconds.", required = true)
      @FormParam("start") long start,
      @Parameter(description = "Clip duration in milliseconds (should be positive).", required = true)
      @FormParam("duration") long duration
  ) {
    SmilResponse smilResponse = null;
    Track trackObj = null;
    try {
      smilResponse = smilService.fromXml(smil);
      trackObj = (Track) MediaPackageElementParser.getFromXml(track);
    } catch (SmilException ex) {
      return Response.status(HttpServletResponse.SC_BAD_REQUEST).entity("SMIL document invalid.").build();
    } catch (MediaPackageException ex) {
      return Response.status(HttpServletResponse.SC_BAD_REQUEST).entity("Track is not valid.").build();
    }
    try {
      smilResponse = smilService.addClip(smilResponse.getSmil(), parentId, trackObj, start, duration);
      return Response.ok(smilResponse).build();
    } catch (SmilException ex) {
      logger.info(ex.getMessage(), ex);
      return Response.status(HttpServletResponse.SC_BAD_REQUEST)
          .entity("SMIL document doesn't contain an element with given parentId.")
          .build();
    }
  }

  @POST
  @Path("addClips")
  @Produces({MediaType.APPLICATION_XML, MediaType.TEXT_XML})
  @Operation(
      summary = "Add several media elements to a SMIL",
      description = "Add new media elements based on given Tracks information and start / duration parameters. "
          + "ParentId specifies where to put the new media."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Add media elements to SMIL successful."),
      @ApiResponse(
          responseCode = "400",
          description = "SMIL document or tracks not valid, the SMIL document doesn't contain an element with given "
              + "parentId, or start plus duration is bigger than the track length"
      )
  })
  public Response addClips(
      @Parameter(description = "SMIL document where to add new media elements.", required = true)
      @FormParam("smil") String smil,
      @Parameter(description = "An element Id, where to add new media. ")
      @FormParam("parentId") String parentId,
      @Parameter(
          description = "Tracks (MediaPackageElements) to add as media elements."
              + "Some information like Track source and flavor will be stored in ParamGroup (in SMIL Head) "
              + "and referenced by paramGroup media element attribute.",
          required = true
      )
      @FormParam("tracks") String tracks,
      @Parameter(
          description = "Track start position in milliseconds. "
              + "The start position will be applied to each media element.",
          required = true
      )
      @FormParam("start") long start,
      @Parameter(
          description = "Clip duration in milliseconds (should be positive). "
              + "The duration will be applied to each media element.",
          required = true
      )
      @FormParam("duration") long duration
  ) {
    SmilResponse smilResponse = null;
    List<Track> tracksList = null;
    try {
      smilResponse = smilService.fromXml(smil);
      tracksList = (List<Track>) MediaPackageElementParser.getArrayFromXml(tracks);
    } catch (SmilException ex) {
      logger.info(ex.getMessage(), ex);
      return Response.status(HttpServletResponse.SC_BAD_REQUEST).entity("SMIL document invalid.").build();
    } catch (MediaPackageException ex) {
      logger.error(ex.getMessage(), ex);
      return Response.status(HttpServletResponse.SC_BAD_REQUEST).entity("Tracks are not valid.").build();
    }

    Track[] tracksArr = tracksList.toArray(new Track[tracksList.size()]);
    try {
      smilResponse = smilService.addClips(smilResponse.getSmil(), parentId, tracksArr, start, duration);
      return Response.ok(smilResponse).build();
    } catch (SmilException ex) {
      logger.info(ex.getMessage(), ex);
      return Response.status(HttpServletResponse.SC_BAD_REQUEST)
          .entity("SMIL document doesn't contain an element with given parentId.")
          .build();
    }
  }

  @POST
  @Path("addMeta")
  @Produces({MediaType.APPLICATION_XML, MediaType.TEXT_XML})
  @Operation(
      summary = "Add a meta element to a SMIL",
      description = "Add a meta element to SMIL head."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The meta element has been added to the SMIL."),
      @ApiResponse(responseCode = "400", description = "SMIL document not valid.")
  })
  public Response addMeta(
      @Parameter(description = "SMIL document where to add a meta element.", required = true)
      @FormParam("smil") String smil,
      @Parameter(description = "Value of meta name attribute.", required = true)
      @FormParam("name") String metaName,
      @Parameter(description = "Value of meta content attribute.", required = true)
      @FormParam("content") String metaContent
  ) {
    SmilResponse smilResponse = null;
    try {
      smilResponse = smilService.fromXml(smil);
    } catch (SmilException ex) {
      return Response.status(HttpServletResponse.SC_BAD_REQUEST).entity("SMIL document invalid.").build();
    }
    smilResponse = smilService.addMeta(smilResponse.getSmil(), metaName, metaContent);
    return Response.ok(smilResponse).build();
  }

  @POST
  @Path("remove")
  @Produces({MediaType.APPLICATION_XML, MediaType.TEXT_XML})
  @Operation(
      summary = "Remove an element from a SMIL",
      description = "Remove an element with given Id from SMIL."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Removing element from SMIL successful."),
      @ApiResponse(responseCode = "400", description = "SMIL document not valid.")
  })
  public Response removeSmilElement(
      @Parameter(description = "SMIL document.", required = true)
      @FormParam("smil") String smil,
      @Parameter(description = "Id of element to remove.", required = true)
      @FormParam("elementId") String elementId
  ) {
    SmilResponse smilResponse = null;
    try {
      smilResponse = smilService.fromXml(smil);
      smilResponse = smilService.removeSmilElement(smilResponse.getSmil(), elementId);
      return Response.ok(smilResponse).build();
    } catch (SmilException ex) {
      logger.info(ex.getMessage(), ex);
      return Response.status(HttpServletResponse.SC_BAD_REQUEST).entity("SMIL document invalid.").build();
    }
  }

  /**
   * Set {@link SmilService}.
   *
   * @param smilService {@link SmilService} to set
   */
  @Reference
  public void setSmilService(SmilService smilService) {
    this.smilService = smilService;
  }
}
