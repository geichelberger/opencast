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

package org.opencastproject.graphql.datafetcher.user;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.opencastproject.graphql.datafetcher.ParameterDataFetcher;
import org.opencastproject.graphql.exception.GraphQLRuntimeException;
import org.opencastproject.graphql.exception.OpencastErrorType;
import org.opencastproject.graphql.execution.context.OpencastContext;
import org.opencastproject.graphql.execution.context.OpencastContextManager;
import org.opencastproject.graphql.user.GqlUser;
import org.opencastproject.graphql.user.GqlUserList;
import org.opencastproject.graphql.user.UserPrivileges;
import org.opencastproject.security.api.JaxbOrganization;
import org.opencastproject.security.api.JaxbRole;
import org.opencastproject.security.api.JaxbUser;
import org.opencastproject.security.api.User;
import org.opencastproject.security.api.UserDirectoryService;

import org.easymock.EasyMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;

import java.util.List;
import java.util.Set;

import graphql.schema.DataFetchingEnvironment;

class UserOffsetDataFetcherTest {

  private static final JaxbOrganization ORGANIZATION = new JaxbOrganization("mh_default_org", "Default", null,
      "ROLE_ORG_ADMIN", "ROLE_ANONYMOUS", null);

  private OpencastContext context;
  private DataFetchingEnvironment environment;

  @BeforeEach
  @SuppressWarnings("unchecked")
  void setUp() {
    User alice = user("alice", "Alice Example", "alice@example.org", "ROLE_STUDENT");
    User bob = user("bob", "Bob Example", "bob@example.org", "ROLE_TEACHER");

    UserDirectoryService userDirectoryService = EasyMock.createMock(UserDirectoryService.class);
    EasyMock.expect(userDirectoryService.getUsers()).andReturn(List.of(alice, bob)).anyTimes();

    BundleContext bundleContext = EasyMock.createMock(BundleContext.class);
    ServiceReference<UserDirectoryService> reference = EasyMock.createMock(ServiceReference.class);
    EasyMock.expect(bundleContext.getServiceReference(UserDirectoryService.class)).andReturn(reference).anyTimes();
    EasyMock.expect(bundleContext.getService(reference)).andReturn(userDirectoryService).anyTimes();

    environment = EasyMock.createNiceMock(DataFetchingEnvironment.class);
    EasyMock.replay(userDirectoryService, bundleContext, environment);

    context = OpencastContextManager.initiateContext(bundleContext);
    context.setOrganization(ORGANIZATION);
  }

  @AfterEach
  void tearDown() {
    OpencastContextManager.clearContext();
  }

  @Test
  void hidesEmailAndRolesFromRegularUsers() {
    context.setUser(user("carol", "Carol", "carol@example.org", "ROLE_USER"));

    GqlUserList result = new UserOffsetDataFetcher().get(context, environment);

    assertEquals(2, result.nodes().size());
    for (GqlUser user : result.nodes()) {
      assertNull(user.email());
      assertTrue(user.roles().isEmpty());
    }
    assertEquals("Alice Example", result.nodes().get(0).name());
  }

  @Test
  void doesNotMatchEmailAddressesForRegularUsers() {
    context.setUser(user("carol", "Carol", "carol@example.org", "ROLE_USER"));

    GqlUserList result = new UserOffsetDataFetcher().withFilter("alice@example").get(context, environment);

    assertEquals(0L, result.totalCount());
  }

  @Test
  void showsEmailAndRolesToUserAdministrators() {
    for (String adminRole : List.of("ROLE_ADMIN", "ROLE_ORG_ADMIN", UserPrivileges.USERS_VIEW_ROLE)) {
      context.setUser(user("admin", "Admin", "admin@example.org", adminRole));

      GqlUserList result = new UserOffsetDataFetcher().withFilter("alice@example").get(context, environment);

      assertEquals(1L, result.totalCount(), adminRole);
      GqlUser alice = result.nodes().get(0);
      assertEquals("alice@example.org", alice.email(), adminRole);
      assertTrue(alice.roles().contains("ROLE_STUDENT"), adminRole);
    }
  }

  @Test
  void rejectsLimitsOutsideTheAllowedRange() {
    context.setUser(user("admin", "Admin", "admin@example.org", "ROLE_ADMIN"));

    // 0 would mean "no limit" further down, so it must not be passed through
    for (int limit : new int[] { 0, -1, ParameterDataFetcher.MAX_PAGE_SIZE + 1 }) {
      GraphQLRuntimeException e = assertThrows(GraphQLRuntimeException.class,
          () -> new UserOffsetDataFetcher().get(context, arguments(limit, 0)));
      assertEquals(OpencastErrorType.BadRequest, e.getErrorType(), "limit " + limit);
    }
  }

  @Test
  void rejectsNegativeOffset() {
    context.setUser(user("admin", "Admin", "admin@example.org", "ROLE_ADMIN"));

    GraphQLRuntimeException e = assertThrows(GraphQLRuntimeException.class,
        () -> new UserOffsetDataFetcher().get(context, arguments(10, -1)));
    assertEquals(OpencastErrorType.BadRequest, e.getErrorType());
  }

  @Test
  void acceptsMaximumPageSize() {
    context.setUser(user("admin", "Admin", "admin@example.org", "ROLE_ADMIN"));

    GqlUserList result = new UserOffsetDataFetcher()
        .get(context, arguments(ParameterDataFetcher.MAX_PAGE_SIZE, 1));

    assertEquals(2L, result.totalCount());
    assertEquals(1, result.nodes().size());
  }

  private static DataFetchingEnvironment arguments(int limit, int offset) {
    DataFetchingEnvironment env = EasyMock.createNiceMock(DataFetchingEnvironment.class);
    EasyMock.expect(env.getArgument("limit")).andReturn(limit).anyTimes();
    EasyMock.expect(env.getArgument("offset")).andReturn(offset).anyTimes();
    EasyMock.replay(env);
    return env;
  }

  private static User user(String username, String name, String email, String role) {
    return new JaxbUser(username, null, name, email, "test", ORGANIZATION,
        Set.of(new JaxbRole(role, ORGANIZATION)));
  }

}
