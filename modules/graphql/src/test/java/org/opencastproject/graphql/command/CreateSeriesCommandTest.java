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
import org.opencastproject.elasticsearch.index.objects.series.Series;
import org.opencastproject.graphql.exception.GraphQLRuntimeException;
import org.opencastproject.graphql.exception.OpencastErrorType;
import org.opencastproject.graphql.series.GqlSeries;
import org.opencastproject.graphql.type.input.AccessControlItemInput;
import org.opencastproject.graphql.type.input.AccessControlListInput;
import org.opencastproject.graphql.type.input.GqlCommonSeriesMetadataInput;
import org.opencastproject.index.service.api.IndexService;
import org.opencastproject.index.service.catalog.adapter.series.CommonSeriesCatalogUIAdapter;
import org.opencastproject.index.service.exception.IndexServiceException;
import org.opencastproject.metadata.dublincore.MetadataList;
import org.opencastproject.security.api.AccessControlEntry;
import org.opencastproject.security.api.AccessControlList;
import org.opencastproject.security.api.Organization;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.security.api.User;
import org.opencastproject.series.api.SeriesService;

import org.easymock.Capture;
import org.easymock.EasyMock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public class CreateSeriesCommandTest extends AbstractCommandTest {

  private static final String SERIES_ID = "series-1";
  private static final String ORG_ID = "mh_default_org";
  private static final String SERIES_FLAVOR = "dublincore/series";

  private ElasticsearchIndex index;
  private IndexService indexService;
  private Organization organization;
  private User user;

  @BeforeEach
  void setUp() throws Exception {
    index = EasyMock.createMock(ElasticsearchIndex.class);
    indexService = EasyMock.createMock(IndexService.class);
    organization = EasyMock.createNiceMock(Organization.class);
    EasyMock.expect(organization.getId()).andReturn(ORG_ID).anyTimes();
    user = EasyMock.createNiceMock(User.class);
    EasyMock.replay(organization, user);
    context.setOrganization(organization);
    context.setUser(user);

    mockService(ElasticsearchIndex.class, index);
    mockService(IndexService.class, indexService);
    // CreateSeriesCommand looks the series service up but does not use it
    mockService(SeriesService.class, null);

    EasyMock.expect(indexService.getCommonSeriesCatalogUIAdapter())
        .andReturn(loadCatalogUIAdapter(new CommonSeriesCatalogUIAdapter(), "/series-catalog.properties"))
        .anyTimes();
  }

  @Test
  void createsSeriesWithMetadataAndAcl() throws Exception {
    Map<String, Object> metadata = new LinkedHashMap<>();
    metadata.put("title", "Created Series");
    stubMetadataArgument(metadata);

    Capture<MetadataList> capturedMetadata = Capture.newInstance();
    Capture<Optional<AccessControlList>> capturedAcl = Capture.newInstance();
    EasyMock.expect(indexService.createSeries(EasyMock.capture(capturedMetadata), EasyMock.anyObject(),
        EasyMock.capture(capturedAcl), EasyMock.eq(Optional.empty()))).andReturn(SERIES_ID);
    Series series = new Series(SERIES_ID, ORG_ID);
    series.setTitle("Created Series");
    EasyMock.expect(index.getSeries(SERIES_ID, organization, user)).andReturn(Optional.of(series));

    EasyMock.replay(bundleContext, index, indexService, environment);

    GqlSeries result = buildCommand(aclInput(null, "ROLE_USER", "read", "write")).execute();

    assertEquals(SERIES_ID, result.id());
    assertEquals("Created Series", result.title());
    assertEquals("Created Series", capturedMetadata.getValue().getMetadataByFlavor(SERIES_FLAVOR)
        .getOutputFields().get("title").getValue());
    assertTrue(capturedAcl.getValue().isPresent());
    Set<String> entries = capturedAcl.getValue().get().getEntries().stream()
        .map(e -> e.getRole() + ":" + e.getAction())
        .collect(Collectors.toSet());
    assertEquals(Set.of("ROLE_USER:read", "ROLE_USER:write"), entries);

    EasyMock.verify(index, indexService, environment);
  }

  @Test
  void mergesManagedAclIntoNewSeriesAcl() throws Exception {
    AclServiceFactory aclServiceFactory = EasyMock.createMock(AclServiceFactory.class);
    SecurityService securityService = EasyMock.createMock(SecurityService.class);
    AclService aclService = EasyMock.createMock(AclService.class);
    ManagedAcl managedAcl = EasyMock.createMock(ManagedAcl.class);
    mockService(AclServiceFactory.class, aclServiceFactory);
    mockService(SecurityService.class, securityService);

    stubMetadataArgument(new LinkedHashMap<>());

    EasyMock.expect(securityService.getOrganization()).andReturn(organization);
    EasyMock.expect(aclServiceFactory.serviceFor(organization)).andReturn(aclService);
    EasyMock.expect(aclService.getAcl(5L)).andReturn(Optional.of(managedAcl));
    EasyMock.expect(managedAcl.getAcl())
        .andReturn(new AccessControlList(new AccessControlEntry("ROLE_ADMIN", "write", true)));

    Capture<Optional<AccessControlList>> capturedAcl = Capture.newInstance();
    EasyMock.expect(indexService.createSeries(EasyMock.anyObject(MetadataList.class), EasyMock.anyObject(),
        EasyMock.capture(capturedAcl), EasyMock.anyObject())).andReturn(SERIES_ID);
    EasyMock.expect(index.getSeries(SERIES_ID, organization, user))
        .andReturn(Optional.of(new Series(SERIES_ID, ORG_ID)));

    EasyMock.replay(bundleContext, index, indexService, environment, aclServiceFactory, securityService,
        aclService, managedAcl);

    buildCommand(aclInput(5L, "ROLE_USER", "read")).execute();

    Set<String> entries = capturedAcl.getValue().get().getEntries().stream()
        .map(e -> e.getRole() + ":" + e.getAction())
        .collect(Collectors.toSet());
    assertEquals(Set.of("ROLE_USER:read", "ROLE_ADMIN:write"), entries);

    EasyMock.verify(index, indexService, environment, aclServiceFactory, securityService, aclService,
        managedAcl);
  }

  @Test
  void wrapsIndexServiceExceptionAsGraphQLRuntimeException() throws Exception {
    stubMetadataArgument(new LinkedHashMap<>());
    EasyMock.expect(indexService.createSeries(EasyMock.anyObject(MetadataList.class), EasyMock.anyObject(),
        EasyMock.anyObject(), EasyMock.anyObject())).andThrow(new IndexServiceException("boom"));

    EasyMock.replay(bundleContext, index, indexService, environment);

    assertThrows(GraphQLRuntimeException.class,
        () -> buildCommand(aclInput(null, "ROLE_USER", "read")).execute());

    EasyMock.verify(index, indexService, environment);
  }

  @Test
  void failsSoftWhenCreatedSeriesIsNotIndexedYet() throws Exception {
    stubMetadataArgument(new LinkedHashMap<>());
    EasyMock.expect(indexService.createSeries(EasyMock.anyObject(MetadataList.class), EasyMock.anyObject(),
        EasyMock.anyObject(), EasyMock.anyObject())).andReturn(SERIES_ID);
    EasyMock.expect(index.getSeries(SERIES_ID, organization, user)).andReturn(Optional.empty());

    EasyMock.replay(bundleContext, index, indexService, environment);

    assertThrows(GraphQLRuntimeException.class,
        () -> buildCommand(aclInput(null, "ROLE_USER", "read")).execute());

    EasyMock.verify(index, indexService, environment);
  }

  @Test
  void rejectsUnknownMetadataFieldWithoutCreatingSeries() throws Exception {
    Map<String, Object> metadata = new LinkedHashMap<>();
    metadata.put("title", "Created Series");
    metadata.put("doesNotExist", "value");
    stubMetadataArgument(metadata);

    // createSeries is not expected, so calling it fails the test
    EasyMock.replay(bundleContext, index, indexService, environment);

    GraphQLRuntimeException e = assertThrows(GraphQLRuntimeException.class,
        () -> buildCommand(aclInput(null, "ROLE_USER", "read")).execute());
    assertEquals(OpencastErrorType.BadRequest, e.getErrorType());
    assertTrue(e.getMessage().contains("doesNotExist"));

    EasyMock.verify(index, indexService, environment);
  }

  @Test
  void buildFailsWhenMetadataInputIsNull() {
    assertThrows(IllegalStateException.class, () -> CreateSeriesCommand
        .create(null, aclInput(null, "ROLE_USER", "read"))
        .environment(environment)
        .build());
  }

  @Test
  void buildFailsWhenAclInputIsNull() {
    assertThrows(IllegalStateException.class, () -> CreateSeriesCommand
        .create(new GqlCommonSeriesMetadataInput(), null)
        .environment(environment)
        .build());
  }

  @Test
  void buildFailsWhenEnvironmentIsMissing() {
    assertThrows(IllegalStateException.class, () -> CreateSeriesCommand
        .create(new GqlCommonSeriesMetadataInput(), aclInput(null, "ROLE_USER", "read"))
        .build());
  }

  private AbstractCommand<GqlSeries> buildCommand(AccessControlListInput aclInput) {
    return CreateSeriesCommand.create(new GqlCommonSeriesMetadataInput(), aclInput)
        .environment(environment)
        .build();
  }

  private static AccessControlListInput aclInput(Long managedAclId, String role, String... actions) {
    return new AccessControlListInput(managedAclId, List.of(new AccessControlItemInput(role, List.of(actions))));
  }

  private void stubMetadataArgument(Map<String, Object> metadata) {
    EasyMock.expect(environment.getArgument("metadata")).andReturn(metadata);
  }

}
