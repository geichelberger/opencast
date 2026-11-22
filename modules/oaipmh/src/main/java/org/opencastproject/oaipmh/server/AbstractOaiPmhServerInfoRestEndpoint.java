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
package org.opencastproject.oaipmh.server;

import static org.opencastproject.util.RestUtil.R.ok;

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

/** Assistant REST endpoint to support a distributed deployment of the {@link OaiPmhServer}. */
public abstract class AbstractOaiPmhServerInfoRestEndpoint {
  public abstract OaiPmhServerInfo getOaiPmhServerInfo();

  @GET
  @Path("/hasrepo/{repoId}")
  @Produces(MediaType.TEXT_PLAIN)
  @Operation(
      summary = "Check whether the OAI-PMH server knows a repository",
      description = "Ask if the OAI-PMH server knows about a repository"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "true|false")
  })
  public Response hasRepo(
      @Parameter(description = "The id of the repository", required = true)
      @PathParam("repoId") String repoId
  ) {
    return ok(getOaiPmhServerInfo().hasRepo(repoId));
  }

  @GET
  @Path("/mountpoint")
  @Produces(MediaType.TEXT_PLAIN)
  @Operation(
      summary = "Get the mount point of the OAI-PMH server",
      description = "Ask for the mount point of the OAI-PMH server"
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "The mount point")
  })
  public Response getMountPoint() {
    return ok(getOaiPmhServerInfo().getMountPoint());
  }
}
