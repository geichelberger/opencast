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

package org.opencastproject.kernel.bundleinfo;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static javax.ws.rs.core.MediaType.TEXT_PLAIN_TYPE;
import static org.opencastproject.util.RestUtil.R.notFound;
import static org.opencastproject.util.RestUtil.R.ok;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Dictionary;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

import javax.ws.rs.DELETE;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

/** Bundle information via REST. */
@Tag(
    name = "System Bundle Info",
    description = "The system bundle info endpoint yields information about the running OSGi bundles of Opencast."
)
public abstract class BundleInfoRestEndpoint {

  private static final Logger logger = LoggerFactory.getLogger(BundleInfoRestEndpoint.class);

  private static final String DEFAULT_BUNDLE_PREFIX = "opencast";

  protected abstract BundleInfoDb getDb();

  private long lastModified = 0;

  @Activate
  public void activate(ComponentContext cc) {
    Dictionary<String, String> headers = cc.getBundleContext().getBundle().getHeaders();

    if (headers != null) {
      String lastModifiedObj = headers.get("Bnd-LastModified");

      if (lastModifiedObj != null) {
        lastModified = Long.valueOf(lastModifiedObj);
      }
    }
  }

  @GET
  // path prefix "bundles" is contained here and not in the path annotation of the class
  // See https://opencast.jira.com/browse/MH-9768
  @Path("bundles/list")
  @Produces(APPLICATION_JSON)
  @Operation(
      summary = "List the running bundles",
      description = "Return a list of all running bundles on the whole cluster."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "A list of bundles.")
  })
  public Response getVersions() {
    JsonArray bundleInfos = new JsonArray();
    for (BundleInfo bundle : getDb().getBundles()) {
      bundleInfos.add(bundleInfo(bundle));
    }

    JsonObject json = new JsonObject();
    json.add("bundleInfos", bundleInfos);
    json.addProperty("count", bundleInfos.size());
    return ok(json);
  }

  /** Return true if all bundles have the same bundle version and build number. */
  @GET
  @Path("bundles/check")
  @Operation(
      summary = "Check the bundle versions across the cluster",
      description = "Check if all bundles throughout the cluster have the same OSGi bundle version and build number."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "true/false"),
      @ApiResponse(responseCode = "404", description = "cannot find any bundles with the given prefix")
  })
  public Response checkBundles(
      @Parameter(
          description = "The bundle name prefixes to check. Defaults to '" + DEFAULT_BUNDLE_PREFIX + "'.",
          example = DEFAULT_BUNDLE_PREFIX
      )
      @DefaultValue(DEFAULT_BUNDLE_PREFIX) @QueryParam("prefix") List<String> prefixes
  ) {
    return withBundles(prefixes, infos -> {
      final String bundleVersion = infos.get(0).getBundleVersion();
      final Optional<String> buildNumber = infos.get(0).getBuildNumber();
      for (BundleInfo a : infos) {
        if (!Objects.equals(a.getBundleVersion(), bundleVersion) || !Objects.equals(a.getBuildNumber(), buildNumber)) {
          return ok(TEXT_PLAIN_TYPE, "false");
        }
      }
      return ok(TEXT_PLAIN_TYPE, "true");
    });
  }

  /** Return the common version of all bundles matching the given prefix. */
  @GET
  @Path("bundles/version")
  @Produces(APPLICATION_JSON)
  @Operation(
      summary = "Get the common bundle version",
      description = "Return the common OSGi build version and build number of all bundles matching the given prefix."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "200", description = "Version structure"),
      @ApiResponse(responseCode = "404", description = "No bundles with the given prefix")
  })
  public Response getBundleVersion(
      @Parameter(
          description = "The bundle name prefixes to check. Defaults to '" + DEFAULT_BUNDLE_PREFIX + "'.",
          example = DEFAULT_BUNDLE_PREFIX
      )
      @DefaultValue(DEFAULT_BUNDLE_PREFIX) @QueryParam("prefix") List<String> prefixes
  ) {
    return withBundles(prefixes, infos -> {
      final Set<BundleVersion> versions = new HashSet<>();
      for (BundleInfo bundle : infos) {
        versions.add(bundle.getVersion());
      }
      final BundleInfo example = infos.get(0);
      switch (versions.size()) {
        case 0:
          // no versions...
          throw new Error("bug");
        case 1: {
          // all versions align
          JsonObject json = new JsonObject();
          json.addProperty("consistent", true);
          merge(json, fullVersionJson(example.getVersion()));
          json.addProperty("last-modified", lastModified);
          return ok(json);
        }
        default: {
          // multiple versions found
          JsonArray versionsJson = new JsonArray();
          for (BundleVersion version : versions) {
            versionsJson.add(fullVersionJson(version));
          }
          JsonObject json = new JsonObject();
          json.addProperty("consistent", false);
          json.add("versions", versionsJson);
          return ok(json);
        }
      }
    });
  }

  @DELETE
  @Path("bundles/host")
  @Operation(
      summary = "Remove the tracked bundles of a host",
      description = "Removes the tracked bundles for a host. This is done automatically when you shut down "
          + "Opencast. But this endpoint can be used to force this in case e.g. a machine got dropped. Make sure the "
          + "host is actually gone! The database will be automatically rebuilt when Opencast on that host is "
          + "(re)started."
  )
  @ApiResponses({
      @ApiResponse(responseCode = "204", description = "The tracked bundles of the host were removed")
  })
  public Response clearHost(
      @Parameter(description = "The name of the host to clear", required = true)
      @QueryParam("host") String host
  ) {
    logger.debug("Removing tracked bundles of host: {}", host);
    getDb().clear(host);
    return Response.noContent().build();
  }

  public static JsonObject fullVersionJson(BundleVersion version) {
    JsonObject json = new JsonObject();
    json.addProperty("version", version.getBundleVersion());
    // an absent build number is left out entirely rather than serialized as null
    version.getBuildNumber().ifPresent(buildNumber -> json.addProperty("buildNumber", buildNumber));
    return json;
  }

  public static JsonObject bundleInfoJson(BundleInfo bundle) {
    JsonObject json = new JsonObject();
    json.addProperty("host", bundle.getHost());
    json.addProperty("bundleSymbolicName", bundle.getBundleSymbolicName());
    json.addProperty("bundleId", bundle.getBundleId());
    merge(json, fullVersionJson(bundle.getVersion()));
    return json;
  }

  public static JsonObject bundleInfo(BundleInfo bundle) {
    return bundleInfoJson(bundle);
  }

  /** Copy all members of <code>source</code> into <code>target</code>, overwriting on conflict. */
  private static void merge(JsonObject target, JsonObject source) {
    for (String key : source.keySet()) {
      target.add(key, source.get(key));
    }
  }

  /** Run <code>f</code> if there is at least one bundle matching the given prefixes. */
  private Response withBundles(List<String> prefixes, Function<List<BundleInfo>, Response> f) {
    final List<BundleInfo> info = getDb().getBundles(prefixes.toArray(String[]::new));
    if (info.size() > 0) {
      return f.apply(info);
    } else {
      return notFound("No bundles match one of the given prefixes");
    }
  }
}
