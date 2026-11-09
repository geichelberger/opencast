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

package org.opencastproject.graphql.command;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.opencastproject.authorization.xacml.manager.api.AclService;
import org.opencastproject.authorization.xacml.manager.api.AclServiceFactory;
import org.opencastproject.authorization.xacml.manager.api.ManagedAcl;
import org.opencastproject.elasticsearch.api.SearchIndexException;
import org.opencastproject.elasticsearch.index.ElasticsearchIndex;
import org.opencastproject.elasticsearch.index.objects.event.Event;
import org.opencastproject.graphql.event.GqlEvent;
import org.opencastproject.graphql.exception.GraphQLNotFoundException;
import org.opencastproject.graphql.exception.GraphQLRuntimeException;
import org.opencastproject.graphql.exception.GraphQLUnauthorizedException;
import org.opencastproject.graphql.exception.OpencastErrorType;
import org.opencastproject.index.service.api.IndexService;
import org.opencastproject.index.service.exception.IndexServiceException;
import org.opencastproject.security.api.AccessControlEntry;
import org.opencastproject.security.api.AccessControlList;
import org.opencastproject.security.api.Organization;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.security.api.UnauthorizedException;
import org.opencastproject.util.NotFoundException;

import org.easymock.Capture;
import org.easymock.EasyMock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public class UpdateEventAclCommandTest extends AbstractCommandTest {

  private static final String EVENT_ID = "event-1";

  private ElasticsearchIndex index;
  private IndexService indexService;

  @BeforeEach
  void setUp() {
    index = EasyMock.createMock(ElasticsearchIndex.class);
    indexService = EasyMock.createMock(IndexService.class);
    mockService(ElasticsearchIndex.class, index);
    mockService(IndexService.class, indexService);
  }

  @Test
  void updatesAclAndReturnsEvent() throws Exception {
    stubAclArgument(aclArgument(null, "ROLE_USER", "read", "write"));

    Capture<AccessControlList> capturedAcl = Capture.newInstance();
    EasyMock.expect(indexService.updateEventAcl(
        EasyMock.eq(EVENT_ID), EasyMock.capture(capturedAcl), EasyMock.eq(index))).andReturn(null);
    Event event = new Event(EVENT_ID, "mh_default_org");
    event.setTitle("Title");
    EasyMock.expect(indexService.getEvent(EVENT_ID, index)).andReturn(Optional.of(event));

    EasyMock.replay(bundleContext, indexService, environment);

    GqlEvent result = buildCommand().execute();

    assertEquals(EVENT_ID, result.id());
    assertEquals("Title", result.title());
    Set<String> actions = capturedAcl.getValue().getEntries().stream()
        .map(AccessControlEntry::getAction)
        .collect(Collectors.toSet());
    assertEquals(Set.of("read", "write"), actions);
    assertTrue(capturedAcl.getValue().getEntries().stream()
        .allMatch(e -> e.isAllow() && "ROLE_USER".equals(e.getRole())));

    EasyMock.verify(indexService, environment);
  }

  @Test
  void mergesManagedAclWithExplicitEntries() throws Exception {
    AclServiceFactory aclServiceFactory = EasyMock.createMock(AclServiceFactory.class);
    SecurityService securityService = EasyMock.createMock(SecurityService.class);
    AclService aclService = EasyMock.createMock(AclService.class);
    ManagedAcl managedAcl = EasyMock.createMock(ManagedAcl.class);
    Organization organization = EasyMock.createMock(Organization.class);
    mockService(AclServiceFactory.class, aclServiceFactory);
    mockService(SecurityService.class, securityService);

    stubAclArgument(aclArgument(7L, "ROLE_USER", "read"));

    EasyMock.expect(securityService.getOrganization()).andReturn(organization);
    EasyMock.expect(aclServiceFactory.serviceFor(organization)).andReturn(aclService);
    EasyMock.expect(aclService.getAcl(7L)).andReturn(Optional.of(managedAcl));
    EasyMock.expect(managedAcl.getAcl())
        .andReturn(new AccessControlList(new AccessControlEntry("ROLE_ADMIN", "write", true)));

    Capture<AccessControlList> capturedAcl = Capture.newInstance();
    EasyMock.expect(indexService.updateEventAcl(
        EasyMock.eq(EVENT_ID), EasyMock.capture(capturedAcl), EasyMock.eq(index))).andReturn(null);
    EasyMock.expect(indexService.getEvent(EVENT_ID, index))
        .andReturn(Optional.of(new Event(EVENT_ID, "mh_default_org")));

    EasyMock.replay(bundleContext, indexService, environment, aclServiceFactory, securityService, aclService,
        managedAcl);

    buildCommand().execute();

    Set<String> roles = capturedAcl.getValue().getEntries().stream()
        .map(e -> e.getRole() + ":" + e.getAction())
        .collect(Collectors.toSet());
    assertEquals(Set.of("ROLE_USER:read", "ROLE_ADMIN:write"), roles);

    EasyMock.verify(indexService, environment, aclServiceFactory, securityService, aclService, managedAcl);
  }

  @Test
  void rejectsUnknownManagedAclWithoutUpdatingAcl() throws Exception {
    AclServiceFactory aclServiceFactory = EasyMock.createMock(AclServiceFactory.class);
    SecurityService securityService = EasyMock.createMock(SecurityService.class);
    AclService aclService = EasyMock.createMock(AclService.class);
    Organization organization = EasyMock.createMock(Organization.class);
    mockService(AclServiceFactory.class, aclServiceFactory);
    mockService(SecurityService.class, securityService);

    stubAclArgument(aclArgument(99L, null));

    EasyMock.expect(securityService.getOrganization()).andReturn(organization);
    EasyMock.expect(aclServiceFactory.serviceFor(organization)).andReturn(aclService);
    EasyMock.expect(aclService.getAcl(99L)).andReturn(Optional.empty());

    // updateEventAcl is not expected, so calling it fails the test
    EasyMock.replay(bundleContext, indexService, environment, aclServiceFactory, securityService, aclService);

    GraphQLRuntimeException e = assertThrows(GraphQLRuntimeException.class, () -> buildCommand().execute());
    assertEquals(OpencastErrorType.BadRequest, e.getErrorType());
    assertTrue(e.getMessage().contains("99"));

    EasyMock.verify(indexService, aclServiceFactory, securityService, aclService);
  }

  @Test
  void failsWhenNoAclIsGiven() throws Exception {
    stubAclArgument(null);

    // neither updateEventAcl nor getEvent is expected, so calling them fails the test
    EasyMock.replay(bundleContext, indexService, environment);

    assertThrows(GraphQLRuntimeException.class, () -> buildCommand().execute());
    EasyMock.verify(indexService, environment);
  }

  @Test
  void wrapsIndexServiceExceptionAsGraphQLRuntimeException() throws Exception {
    assertAclUpdateFailureIsMapped(new IndexServiceException("boom"), GraphQLRuntimeException.class);
  }

  @Test
  void wrapsSearchIndexExceptionAsGraphQLRuntimeException() throws Exception {
    assertAclUpdateFailureIsMapped(new SearchIndexException("boom"), GraphQLRuntimeException.class);
  }

  @Test
  void wrapsUnauthorizedExceptionAsGraphQLUnauthorizedException() throws Exception {
    assertAclUpdateFailureIsMapped(new UnauthorizedException("nope"), GraphQLUnauthorizedException.class);
  }

  @Test
  void wrapsNotFoundExceptionAsGraphQLNotFoundException() throws Exception {
    assertAclUpdateFailureIsMapped(new NotFoundException("missing"), GraphQLNotFoundException.class);
  }

  @Test
  void failsSoftWhenEventIsNotIndexedAfterAclUpdate() throws Exception {
    stubAclArgument(aclArgument(null, "ROLE_USER", "read"));
    EasyMock.expect(indexService.updateEventAcl(
        EasyMock.eq(EVENT_ID), EasyMock.anyObject(AccessControlList.class), EasyMock.eq(index))).andReturn(null);
    EasyMock.expect(indexService.getEvent(EVENT_ID, index)).andReturn(Optional.empty());

    EasyMock.replay(bundleContext, indexService, environment);

    assertThrows(GraphQLRuntimeException.class, () -> buildCommand().execute());

    EasyMock.verify(indexService, environment);
  }

  @Test
  void wrapsSearchIndexExceptionWhileLoadingEvent() throws Exception {
    stubAclArgument(aclArgument(null, "ROLE_USER", "read"));
    EasyMock.expect(indexService.updateEventAcl(
        EasyMock.eq(EVENT_ID), EasyMock.anyObject(AccessControlList.class), EasyMock.eq(index))).andReturn(null);
    EasyMock.expect(indexService.getEvent(EVENT_ID, index)).andThrow(new SearchIndexException("boom"));

    EasyMock.replay(bundleContext, indexService, environment);

    assertThrows(GraphQLRuntimeException.class, () -> buildCommand().execute());

    EasyMock.verify(indexService, environment);
  }

  @Test
  void buildFailsWhenEventIdIsNull() {
    assertThrows(IllegalStateException.class, () -> UpdateEventAclCommand.create(null)
        .environment(environment)
        .build());
  }

  @Test
  void buildFailsWhenEventIdIsEmpty() {
    assertThrows(IllegalStateException.class, () -> UpdateEventAclCommand.create("")
        .environment(environment)
        .build());
  }

  @Test
  void buildFailsWhenEnvironmentIsMissing() {
    assertThrows(IllegalStateException.class, () -> UpdateEventAclCommand.create(EVENT_ID).build());
  }

  private void assertAclUpdateFailureIsMapped(Exception thrown, Class<? extends Throwable> expected)
          throws Exception {
    stubAclArgument(aclArgument(null, "ROLE_USER", "read"));
    EasyMock.expect(indexService.updateEventAcl(
        EasyMock.eq(EVENT_ID), EasyMock.anyObject(AccessControlList.class), EasyMock.eq(index))).andThrow(thrown);

    EasyMock.replay(bundleContext, indexService, environment);

    assertThrows(expected, () -> buildCommand().execute());

    EasyMock.verify(indexService, environment);
  }

  private AbstractCommand<GqlEvent> buildCommand() {
    return UpdateEventAclCommand.create(EVENT_ID).environment(environment).build();
  }

  private void stubAclArgument(Map<String, Object> acl) {
    EasyMock.expect(environment.getArgument("acl")).andReturn(acl);
  }

}
