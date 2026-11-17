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

package org.opencastproject.kernel.rest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.Before;
import org.junit.Test;

import java.util.Collections;
import java.util.Map;

import javax.ws.rs.Consumes;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.MediaType;

import io.swagger.v3.jaxrs2.Reader;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.integration.SwaggerConfiguration;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.RequestBody;

public class OpencastOpenApiCustomizerTest {

  private static final String ANY = MediaType.WILDCARD;
  private static final String FORM = MediaType.APPLICATION_FORM_URLENCODED;

  /** Endpoints in the style found throughout Opencast. */
  @Path("/test")
  public static class Endpoint {

    @POST
    @Path("form")
    public String form(@Parameter(description = "The acl", required = true) @FormParam("acl") String acl,
            @FormParam("allowConflict") @DefaultValue("false") boolean allowConflict) {
      return null;
    }

    @PUT
    @Path("{id}/form")
    public String formWithPathParam(@PathParam("id") String id, @FormParam("role") String role) {
      return null;
    }

    @POST
    @Path("declared")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String declaredForm(@FormParam("acl") String acl) {
      return null;
    }

    @POST
    @Path("json")
    @Consumes(MediaType.APPLICATION_JSON)
    public String declaredJson(@FormParam("acl") String acl) {
      return null;
    }

    @POST
    @Path("entity")
    public String entity(Pojo pojo) {
      return null;
    }

    @POST
    @Path("map")
    public String map(Map<String, String> map) {
      return null;
    }

    @POST
    @Path("text")
    public String text(String text) {
      return null;
    }

    @GET
    @Path("none")
    public String none() {
      return null;
    }
  }

  public static class Pojo {
    private String name;
    private int number;

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    public int getNumber() {
      return number;
    }

    public void setNumber(int number) {
      this.number = number;
    }
  }

  private OpenAPI openApi;

  @Before
  public void setUp() {
    openApi = new Reader(new SwaggerConfiguration().openAPI(new OpenAPI()))
        .read(Collections.singleton(Endpoint.class));
  }

  private Content content(final String path, final boolean put) {
    final RequestBody body = put
        ? openApi.getPaths().get(path).getPut().getRequestBody()
        : openApi.getPaths().get(path).getPost().getRequestBody();
    assertNotNull(body);
    return body.getContent();
  }

  @Test
  public void testPrecondition() {
    // Guards against swagger changing what it generates: this is what the customizer is built to handle
    final Content content = content("/test/form", false);
    assertEquals(Collections.singleton(ANY), content.keySet());
  }

  @Test
  public void testFormParamsAreRelabeled() {
    OpencastOpenApiCustomizer.relabelFormRequestBodies(openApi);

    final Content content = content("/test/form", false);
    assertEquals(Collections.singleton(FORM), content.keySet());

    // Everything swagger worked out is kept
    final Schema<?> schema = content.get(FORM).getSchema();
    assertEquals("object", schema.getType());
    assertEquals(2, schema.getProperties().size());
    assertEquals("The acl", ((Schema<?>) schema.getProperties().get("acl")).getDescription());
    assertEquals(Collections.singletonList("acl"), schema.getRequired());
    assertEquals("boolean", ((Schema<?>) schema.getProperties().get("allowConflict")).getType());
    assertEquals(false, ((Schema<?>) schema.getProperties().get("allowConflict")).getDefault());
  }

  @Test
  public void testFormParamsWithPathParamAreRelabeled() {
    OpencastOpenApiCustomizer.relabelFormRequestBodies(openApi);
    assertEquals(Collections.singleton(FORM), content("/test/{id}/form", true).keySet());
  }

  @Test
  public void testExplicitMediaTypesAreKept() {
    OpencastOpenApiCustomizer.relabelFormRequestBodies(openApi);
    assertEquals(Collections.singleton(FORM), content("/test/declared", false).keySet());
    assertEquals(Collections.singleton(MediaType.APPLICATION_JSON), content("/test/json", false).keySet());
  }

  @Test
  public void testOtherBodiesAreKept() {
    OpencastOpenApiCustomizer.relabelFormRequestBodies(openApi);
    assertEquals(Collections.singleton(ANY), content("/test/entity", false).keySet());
    assertEquals(Collections.singleton(ANY), content("/test/map", false).keySet());
    assertEquals(Collections.singleton(ANY), content("/test/text", false).keySet());
  }

  @Test
  public void testOperationsWithoutBodyAreKept() {
    OpencastOpenApiCustomizer.relabelFormRequestBodies(openApi);
    assertNull(openApi.getPaths().get("/test/none").getGet().getRequestBody());
  }

  @Test
  public void testIsIdempotent() {
    OpencastOpenApiCustomizer.relabelFormRequestBodies(openApi);
    OpencastOpenApiCustomizer.relabelFormRequestBodies(openApi);
    assertEquals(Collections.singleton(FORM), content("/test/form", false).keySet());
  }

  @Test
  public void testEmptyDocument() {
    OpencastOpenApiCustomizer.relabelFormRequestBodies(null);
    OpencastOpenApiCustomizer.relabelFormRequestBodies(new OpenAPI());
  }
}
