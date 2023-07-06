/**
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
package org.opencastproject.external.endpoint;

import static io.restassured.RestAssured.given;
import static javax.servlet.http.HttpServletResponse.SC_OK;
import static org.junit.Assert.assertEquals;
import static org.opencastproject.test.rest.RestServiceTestEnv.testEnvForClasses;

import org.opencastproject.test.rest.RestServiceTestEnv;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/** Unit tests for {@link ListProviderEndpoint} */
public class ListProviderEndpointTest {

  /** The REST test environment */
  private static final RestServiceTestEnv env = testEnvForClasses(TestListProviderEndpoint.class);

  private static final JSONParser parser = new JSONParser();

  @BeforeClass
  public static void oneTimeSetUp() {
    env.setUpServer();
  }

  @AfterClass
  public static void oneTimeTearDown() {
    env.tearDownServer();
  }

  @Test
  public void testGetLanguages() throws Exception {
    final String response = given()
            .queryParam("limit", 0)
            .queryParam("offset", 0)
            .expect()
            .statusCode(SC_OK)
            .when()
            .get(env.host("/languages"))
            .asString();

    final JSONObject json = (JSONObject) parser.parse(response);
    assertEquals(3, json.size());

    assertEquals("LANGUAGES.ARABIC",json.get("ara"));
    assertEquals("LANGUAGES.DANISH",json.get("dan"));
  }

  @Test
  public void testGetLicenses() throws Exception {
    final String response = given()
            .queryParam("limit", 0)
            .queryParam("offset", 0)
            .expect()
            .statusCode(SC_OK)
            .when()
            .get(env.host("/licenses"))
            .asString();

    final JSONObject json = (JSONObject) parser.parse(response);
    assertEquals(3, json.size());

    assertEquals("{\"label\":\"EVENTS.LICENSE.CC0\", \"order\":8, \"selectable\": true}",json.get("CC0"));
    assertEquals("{\"label\":\"EVENTS.LICENSE.CCBYSA\", \"order\":3, \"selectable\": true}",json.get("CC-BY-SA"));
  }
}
