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
import org.opencastproject.elasticsearch.index.ElasticsearchIndex;
import org.opencastproject.elasticsearch.index.objects.event.Event;
import org.opencastproject.graphql.event.GqlEvent;
import org.opencastproject.graphql.exception.GraphQLNotFoundException;
import org.opencastproject.graphql.exception.GraphQLRuntimeException;
import org.opencastproject.graphql.exception.GraphQLUnauthorizedException;
import org.opencastproject.graphql.exception.OpencastErrorType;
import org.opencastproject.graphql.type.input.GqlCommonEventMetadataInput;
import org.opencastproject.index.service.api.IndexService;
import org.opencastproject.index.service.catalog.adapter.events.CommonEventCatalogUIAdapter;
import org.opencastproject.index.service.exception.IndexServiceException;
import org.opencastproject.metadata.dublincore.MetadataField;
import org.opencastproject.metadata.dublincore.MetadataList;
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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import graphql.GraphQLContext;

public class UpdateEventCommandTest extends AbstractCommandTest {

  private static final String EVENT_ID = "event-1";
  private static final String EPISODE_FLAVOR = "dublincore/episode";

  private ElasticsearchIndex index;
  private IndexService indexService;
  private CommonEventCatalogUIAdapter catalogUIAdapter;

  @BeforeEach
  void setUp() throws Exception {
    index = EasyMock.createMock(ElasticsearchIndex.class);
    indexService = EasyMock.createMock(IndexService.class);
    catalogUIAdapter = loadCatalogUIAdapter(new CommonEventCatalogUIAdapter(), "/episode-catalog.properties");

    mockService(ElasticsearchIndex.class, index);
    mockService(IndexService.class, indexService);
  }

  @Test
  void updatesEventMetadataAndReturnsUpdatedEvent() throws Exception {
    Map<String, Object> metadata = new LinkedHashMap<>();
    metadata.put("title", "New Title");
    stubMetadataAndAclArguments(metadata, null);

    EasyMock.expect(indexService.getCommonEventCatalogUIAdapter()).andReturn(catalogUIAdapter);

    Capture<MetadataList> capturedMetadataList = Capture.newInstance();
    EasyMock.expect(indexService.updateEventMetadata(
        EasyMock.eq(EVENT_ID), EasyMock.capture(capturedMetadataList), EasyMock.eq(index)))
        .andReturn(null);

    Event updatedEvent = new Event(EVENT_ID, "mh_default_org");
    updatedEvent.setTitle("New Title");
    EasyMock.expect(indexService.getEvent(EVENT_ID, index)).andReturn(Optional.of(updatedEvent));

    expectWritableEvent(index, new Event(EVENT_ID, "mh_default_org"));
    EasyMock.replay(bundleContext, index, indexService, environment);

    GqlEvent result = buildCommand(new GqlCommonEventMetadataInput()).execute();

    assertEquals(EVENT_ID, result.id());
    assertEquals("New Title", result.title());

    MetadataField titleField = capturedMetadataList.getValue()
        .getMetadataByFlavor(EPISODE_FLAVOR)
        .getOutputFields()
        .get("title");
    assertEquals("New Title", titleField.getValue());

    EasyMock.verify(indexService, environment);
  }

  @Test
  void failsSoftWhenEventIsNotIndexedAfterMetadataUpdate() throws Exception {
    stubMetadataAndAclArguments(new LinkedHashMap<>(), null);

    EasyMock.expect(indexService.getCommonEventCatalogUIAdapter()).andReturn(catalogUIAdapter);
    EasyMock.expect(indexService.updateEventMetadata(
        EasyMock.eq(EVENT_ID), EasyMock.anyObject(MetadataList.class), EasyMock.eq(index)))
        .andReturn(null);
    EasyMock.expect(indexService.getEvent(EVENT_ID, index)).andReturn(Optional.empty());

    expectWritableEvent(index, new Event(EVENT_ID, "mh_default_org"));
    EasyMock.replay(bundleContext, index, indexService, environment);

    assertThrows(GraphQLRuntimeException.class, () -> buildCommand(new GqlCommonEventMetadataInput()).execute());

    EasyMock.verify(indexService, environment);
  }

  @Test
  void wrapsIndexServiceExceptionAsGraphQLRuntimeException() throws Exception {
    stubMetadataAndAclArguments(new LinkedHashMap<>(), null);

    EasyMock.expect(indexService.getCommonEventCatalogUIAdapter()).andReturn(catalogUIAdapter);
    EasyMock.expect(indexService.updateEventMetadata(
        EasyMock.eq(EVENT_ID), EasyMock.anyObject(MetadataList.class), EasyMock.eq(index)))
        .andThrow(new IndexServiceException("boom"));

    expectWritableEvent(index, new Event(EVENT_ID, "mh_default_org"));
    EasyMock.replay(bundleContext, index, indexService, environment);

    assertThrows(GraphQLRuntimeException.class, () -> buildCommand(new GqlCommonEventMetadataInput()).execute());

    EasyMock.verify(indexService, environment);
  }

  @Test
  void wrapsUnauthorizedExceptionAsGraphQLUnauthorizedException() throws Exception {
    stubMetadataAndAclArguments(new LinkedHashMap<>(), null);

    EasyMock.expect(indexService.getCommonEventCatalogUIAdapter()).andReturn(catalogUIAdapter);
    EasyMock.expect(indexService.updateEventMetadata(
        EasyMock.eq(EVENT_ID), EasyMock.anyObject(MetadataList.class), EasyMock.eq(index)))
        .andThrow(new UnauthorizedException("not allowed"));

    expectWritableEvent(index, new Event(EVENT_ID, "mh_default_org"));
    EasyMock.replay(bundleContext, index, indexService, environment);

    assertThrows(GraphQLUnauthorizedException.class,
        () -> buildCommand(new GqlCommonEventMetadataInput()).execute());

    EasyMock.verify(indexService, environment);
  }

  @Test
  void wrapsNotFoundExceptionDuringMetadataUpdateAsGraphQLNotFoundException() throws Exception {
    stubMetadataAndAclArguments(new LinkedHashMap<>(), null);

    EasyMock.expect(indexService.getCommonEventCatalogUIAdapter()).andReturn(catalogUIAdapter);
    EasyMock.expect(indexService.updateEventMetadata(
        EasyMock.eq(EVENT_ID), EasyMock.anyObject(MetadataList.class), EasyMock.eq(index)))
        .andThrow(new NotFoundException("no such event"));

    expectWritableEvent(index, new Event(EVENT_ID, "mh_default_org"));
    EasyMock.replay(bundleContext, index, indexService, environment);

    assertThrows(GraphQLNotFoundException.class, () -> buildCommand(new GqlCommonEventMetadataInput()).execute());

    EasyMock.verify(indexService, environment);
  }

  @Test
  void updatesAclEntriesWhenNoManagedAclIdIsProvided() throws Exception {
    Map<String, Object> entry = new LinkedHashMap<>();
    entry.put("role", "ROLE_USER");
    entry.put("action", List.of("read", "write"));
    Map<String, Object> acl = new LinkedHashMap<>();
    acl.put("entries", List.of(entry));

    stubMetadataAndAclArguments(new LinkedHashMap<>(), acl);

    EasyMock.expect(indexService.getCommonEventCatalogUIAdapter()).andReturn(catalogUIAdapter);
    EasyMock.expect(indexService.updateEventMetadata(
        EasyMock.eq(EVENT_ID), EasyMock.anyObject(MetadataList.class), EasyMock.eq(index)))
        .andReturn(null);

    Capture<AccessControlList> capturedAcl = Capture.newInstance();
    EasyMock.expect(indexService.updateEventAcl(
        EasyMock.eq(EVENT_ID), EasyMock.capture(capturedAcl), EasyMock.eq(index)))
        .andReturn(null);

    EasyMock.expect(indexService.getEvent(EVENT_ID, index))
        .andReturn(Optional.of(new Event(EVENT_ID, "mh_default_org")));

    expectWritableEvent(index, new Event(EVENT_ID, "mh_default_org"));
    EasyMock.replay(bundleContext, index, indexService, environment);

    buildCommand(new GqlCommonEventMetadataInput()).execute();

    Set<String> actions = capturedAcl.getValue().getEntries().stream()
        .map(AccessControlEntry::getAction)
        .collect(Collectors.toSet());
    assertEquals(Set.of("read", "write"), actions);
    assertTrue(capturedAcl.getValue().getEntries().stream().allMatch(AccessControlEntry::isAllow));
    assertTrue(capturedAcl.getValue().getEntries().stream()
        .allMatch(e -> "ROLE_USER".equals(e.getRole())));

    EasyMock.verify(indexService, environment);
  }

  @Test
  void mergesManagedAclWhenManagedAclIdIsProvided() throws Exception {
    AclServiceFactory aclServiceFactory = EasyMock.createMock(AclServiceFactory.class);
    SecurityService securityService = EasyMock.createMock(SecurityService.class);
    AclService aclService = EasyMock.createMock(AclService.class);
    ManagedAcl managedAcl = EasyMock.createMock(ManagedAcl.class);
    Organization organization = EasyMock.createMock(Organization.class);

    mockService(AclServiceFactory.class, aclServiceFactory);
    mockService(SecurityService.class, securityService);

    Map<String, Object> acl = new LinkedHashMap<>();
    acl.put("managedAclId", 42L);
    acl.put("entries", List.of());

    stubMetadataAndAclArguments(new LinkedHashMap<>(), acl);

    EasyMock.expect(indexService.getCommonEventCatalogUIAdapter()).andReturn(catalogUIAdapter);
    EasyMock.expect(indexService.updateEventMetadata(
        EasyMock.eq(EVENT_ID), EasyMock.anyObject(MetadataList.class), EasyMock.eq(index)))
        .andReturn(null);

    EasyMock.expect(securityService.getOrganization()).andReturn(organization);
    EasyMock.expect(aclServiceFactory.serviceFor(organization)).andReturn(aclService);
    EasyMock.expect(aclService.getAcl(42L)).andReturn(Optional.of(managedAcl));
    EasyMock.expect(managedAcl.getAcl())
        .andReturn(new AccessControlList(new AccessControlEntry("ROLE_ADMIN", "read", true)));

    Capture<AccessControlList> capturedAcl = Capture.newInstance();
    EasyMock.expect(indexService.updateEventAcl(
        EasyMock.eq(EVENT_ID), EasyMock.capture(capturedAcl), EasyMock.eq(index)))
        .andReturn(null);

    EasyMock.expect(indexService.getEvent(EVENT_ID, index))
        .andReturn(Optional.of(new Event(EVENT_ID, "mh_default_org")));

    expectWritableEvent(index, new Event(EVENT_ID, "mh_default_org"));
    EasyMock.replay(bundleContext, index, indexService, environment, aclServiceFactory, securityService, aclService,
        managedAcl);

    buildCommand(new GqlCommonEventMetadataInput()).execute();

    assertEquals(1, capturedAcl.getValue().getEntries().size());
    AccessControlEntry mergedEntry = capturedAcl.getValue().getEntries().get(0);
    assertEquals("ROLE_ADMIN", mergedEntry.getRole());
    assertEquals("read", mergedEntry.getAction());

    EasyMock.verify(indexService, environment, aclServiceFactory, securityService, aclService, managedAcl);
  }

  @Test
  void rejectsUnknownMetadataFieldWithoutUpdatingEvent() throws Exception {
    Map<String, Object> metadata = new LinkedHashMap<>();
    metadata.put("title", "New Title");
    metadata.put("doesNotExist", "value");
    stubMetadataAndAclArguments(metadata, null);

    EasyMock.expect(indexService.getCommonEventCatalogUIAdapter()).andReturn(catalogUIAdapter);

    // updateEventMetadata is not expected, so calling it fails the test
    expectWritableEvent(index, new Event(EVENT_ID, "mh_default_org"));
    EasyMock.replay(bundleContext, index, indexService, environment);

    GraphQLRuntimeException e = assertThrows(GraphQLRuntimeException.class,
        () -> buildCommand(new GqlCommonEventMetadataInput()).execute());
    assertEquals(OpencastErrorType.BadRequest, e.getErrorType());
    assertTrue(e.getMessage().contains("doesNotExist"));

    EasyMock.verify(indexService);
  }

  @Test
  void buildFailsWhenEventIdIsNull() {
    assertThrows(IllegalStateException.class, () -> UpdateEventCommand
        .create(null, new GqlCommonEventMetadataInput())
        .environment(environment)
        .build());
  }

  @Test
  void buildFailsWhenEventIdIsEmpty() {
    assertThrows(IllegalStateException.class, () -> UpdateEventCommand
        .create("", new GqlCommonEventMetadataInput())
        .environment(environment)
        .build());
  }

  @Test
  void buildFailsWhenMetadataInputIsNull() {
    assertThrows(IllegalStateException.class, () -> UpdateEventCommand
        .create(EVENT_ID, null)
        .environment(environment)
        .build());
  }

  @Test
  void buildFailsWhenEnvironmentIsMissing() {
    assertThrows(IllegalStateException.class, () -> UpdateEventCommand
        .create(EVENT_ID, new GqlCommonEventMetadataInput())
        .build());
  }

  private AbstractCommand<GqlEvent> buildCommand(GqlCommonEventMetadataInput metadataInput) {
    return UpdateEventCommand.create(EVENT_ID, metadataInput)
        .environment(environment)
        .build();
  }

  private void stubMetadataAndAclArguments(Map<String, Object> metadata, Map<String, Object> acl) {
    EasyMock.expect(environment.getArgument("metadata")).andReturn(metadata);
    // Only reached when updating the metadata does not throw, so tolerate zero invocations too.
    EasyMock.expect(environment.getArgument("acl")).andReturn(acl).anyTimes();
    EasyMock.expect(environment.getGraphQlContext()).andReturn(GraphQLContext.newContext().build()).anyTimes();
    EasyMock.expect(environment.getLocale()).andReturn(Locale.ENGLISH).anyTimes();
  }

}
