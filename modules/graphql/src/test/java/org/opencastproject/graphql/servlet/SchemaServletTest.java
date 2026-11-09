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

package org.opencastproject.graphql.servlet;

import org.opencastproject.graphql.schema.SchemaService;
import org.opencastproject.security.api.JaxbOrganization;
import org.opencastproject.security.api.JaxbRole;
import org.opencastproject.security.api.JaxbUser;
import org.opencastproject.security.api.SecurityService;

import org.easymock.EasyMock;
import org.junit.jupiter.api.Test;

import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

class SchemaServletTest {

  @Test
  void refusesSchemaToAnonymousUsers() throws Exception {
    JaxbOrganization organization = new JaxbOrganization("mh_default_org");
    SecurityService securityService = EasyMock.createMock(SecurityService.class);
    EasyMock.expect(securityService.getOrganization()).andReturn(organization).anyTimes();
    EasyMock.expect(securityService.getUser()).andReturn(new JaxbUser("anonymous", null, organization,
        Set.of(new JaxbRole("ROLE_ANONYMOUS", organization)))).anyTimes();
    // no expectations: building the schema would fail the test
    SchemaService schemaService = EasyMock.createMock(SchemaService.class);

    HttpServletRequest request = EasyMock.createMock(HttpServletRequest.class);
    HttpServletResponse response = EasyMock.createNiceMock(HttpServletResponse.class);
    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication required");
    EasyMock.expectLastCall();
    EasyMock.replay(securityService, schemaService, request, response);

    new SchemaServlet(schemaService, securityService).doGet(request, response);

    EasyMock.verify(schemaService, response);
  }

}
