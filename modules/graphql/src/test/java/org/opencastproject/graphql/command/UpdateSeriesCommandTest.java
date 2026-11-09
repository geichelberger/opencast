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
import org.opencastproject.elasticsearch.index.ElasticsearchIndex;
import org.opencastproject.elasticsearch.index.objects.series.Series;
import org.opencastproject.graphql.exception.GraphQLNotFoundException;
import org.opencastproject.graphql.exception.GraphQLRuntimeException;
import org.opencastproject.graphql.exception.GraphQLUnauthorizedException;
import org.opencastproject.graphql.exception.OpencastErrorType;
import org.opencastproject.graphql.series.GqlSeries;
import org.opencastproject.graphql.type.input.GqlCommonSeriesMetadataInput;
import org.opencastproject.index.service.api.IndexService;
import org.opencastproject.index.service.catalog.adapter.series.CommonSeriesCatalogUIAdapter;
import org.opencastproject.index.service.exception.IndexServiceException;
import org.opencastproject.metadata.dublincore.MetadataList;
import org.opencastproject.security.api.AccessControlList;
import org.opencastproject.security.api.Organization;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.security.api.UnauthorizedException;
import org.opencastproject.security.api.User;
import org.opencastproject.series.api.SeriesService;
import org.opencastproject.util.NotFoundException;

import org.easymock.Capture;
import org.easymock.EasyMock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public class UpdateSeriesCommandTest extends AbstractCommandTest {

  private static final String SERIES_ID = "series-1";
  private static final String ORG_ID = "mh_default_org";
  private static final String SERIES_FLAVOR = "dublincore/series";

  private ElasticsearchIndex index;
  private IndexService indexService;
  private SeriesService seriesService;
  private Organization organization;
  private User user;

  @BeforeEach
  void setUp() throws Exception {
    index = EasyMock.createMock(ElasticsearchIndex.class);
    indexService = EasyMock.createMock(IndexService.class);
    seriesService = EasyMock.createMock(SeriesService.class);
    organization = EasyMock.createNiceMock(Organization.class);
    EasyMock.expect(organization.getId()).andReturn(ORG_ID).anyTimes();
    user = EasyMock.createNiceMock(User.class);
    EasyMock.replay(organization, user);
    context.setOrganization(organization);
    context.setUser(user);

    mockService(ElasticsearchIndex.class, index);
    mockService(IndexService.class, indexService);
    mockService(SeriesService.class, seriesService);

    EasyMock.expect(indexService.getCommonSeriesCatalogUIAdapter())
        .andReturn(loadCatalogUIAdapter(new CommonSeriesCatalogUIAdapter(), "/series-catalog.properties"))
        .anyTimes();
  }

  @Test
  void updatesSeriesMetadataAndReturnsSeries() throws Exception {
    Map<String, Object> metadata = new LinkedHashMap<>();
    metadata.put("title", "New Series Title");
    metadata.put("description", "New Description");
    stubArguments(metadata, null);

    Capture<MetadataList> capturedMetadata = Capture.newInstance();
    EasyMock.expect(indexService.updateAllSeriesMetadata(
        EasyMock.eq(SERIES_ID), EasyMock.capture(capturedMetadata), EasyMock.eq(index))).andReturn(null);
    Series series = new Series(SERIES_ID, ORG_ID);
    series.setTitle("New Series Title");
    EasyMock.expect(index.getSeries(SERIES_ID, organization, user)).andReturn(Optional.of(series));

    EasyMock.replay(bundleContext, index, indexService, seriesService, environment);

    GqlSeries result = buildCommand().execute();

    assertEquals(SERIES_ID, result.id());
    assertEquals("New Series Title", result.title());
    var fields = capturedMetadata.getValue().getMetadataByFlavor(SERIES_FLAVOR).getOutputFields();
    assertEquals("New Series Title", fields.get("title").getValue());
    assertEquals("New Description", fields.get("description").getValue());

    EasyMock.verify(index, indexService, seriesService, environment);
  }

  @Test
  void updatesSeriesAclWhenAclIsGiven() throws Exception {
    stubArguments(new LinkedHashMap<>(), aclArgument(null, "ROLE_USER", "read"));

    EasyMock.expect(indexService.updateAllSeriesMetadata(
        EasyMock.eq(SERIES_ID), EasyMock.anyObject(MetadataList.class), EasyMock.eq(index))).andReturn(null);
    Capture<AccessControlList> capturedAcl = Capture.newInstance();
    EasyMock.expect(seriesService.updateAccessControl(EasyMock.eq(SERIES_ID), EasyMock.capture(capturedAcl)))
        .andReturn(true);
    EasyMock.expect(index.getSeries(SERIES_ID, organization, user))
        .andReturn(Optional.of(new Series(SERIES_ID, ORG_ID)));

    EasyMock.replay(bundleContext, index, indexService, seriesService, environment);

    buildCommand().execute();

    Set<String> entries = capturedAcl.getValue().getEntries().stream()
        .map(e -> e.getRole() + ":" + e.getAction())
        .collect(Collectors.toSet());
    assertEquals(Set.of("ROLE_USER:read"), entries);

    EasyMock.verify(index, indexService, seriesService, environment);
  }

  @Test
  void wrapsIndexServiceExceptionAsGraphQLRuntimeException() throws Exception {
    assertMetadataUpdateFailureIsMapped(new IndexServiceException("boom"), GraphQLRuntimeException.class);
  }

  @Test
  void wrapsUnauthorizedExceptionAsGraphQLUnauthorizedException() throws Exception {
    assertMetadataUpdateFailureIsMapped(new UnauthorizedException("nope"), GraphQLUnauthorizedException.class);
  }

  @Test
  void wrapsNotFoundExceptionAsGraphQLNotFoundException() throws Exception {
    assertMetadataUpdateFailureIsMapped(new NotFoundException("missing"), GraphQLNotFoundException.class);
  }

  @Test
  void failsSoftWhenSeriesIsNotIndexedAfterUpdate() throws Exception {
    stubArguments(new LinkedHashMap<>(), null);
    EasyMock.expect(indexService.updateAllSeriesMetadata(
        EasyMock.eq(SERIES_ID), EasyMock.anyObject(MetadataList.class), EasyMock.eq(index))).andReturn(null);
    EasyMock.expect(index.getSeries(SERIES_ID, organization, user)).andReturn(Optional.empty());

    EasyMock.replay(bundleContext, index, indexService, seriesService, environment);

    assertThrows(GraphQLRuntimeException.class, () -> buildCommand().execute());

    EasyMock.verify(index, indexService, seriesService, environment);
  }

  @Test
  void rejectsUnknownManagedAclWithoutUpdatingSeries() throws Exception {
    AclServiceFactory aclServiceFactory = EasyMock.createMock(AclServiceFactory.class);
    SecurityService securityService = EasyMock.createMock(SecurityService.class);
    AclService aclService = EasyMock.createMock(AclService.class);
    mockService(AclServiceFactory.class, aclServiceFactory);
    mockService(SecurityService.class, securityService);
    stubArguments(new LinkedHashMap<>(), aclArgument(99L, "ROLE_USER", "read"));

    EasyMock.expect(securityService.getOrganization()).andReturn(organization);
    EasyMock.expect(aclServiceFactory.serviceFor(organization)).andReturn(aclService);
    EasyMock.expect(aclService.getAcl(99L)).andReturn(Optional.empty());

    // neither the metadata nor the ACL update is expected, so calling them fails the test
    EasyMock.replay(bundleContext, index, indexService, seriesService, environment, aclServiceFactory,
        securityService, aclService);

    GraphQLRuntimeException e = assertThrows(GraphQLRuntimeException.class, () -> buildCommand().execute());
    assertEquals(OpencastErrorType.BadRequest, e.getErrorType());

    EasyMock.verify(index, indexService, seriesService, aclServiceFactory, securityService, aclService);
  }

  @Test
  void rejectsUnknownMetadataFieldWithoutUpdatingSeries() throws Exception {
    Map<String, Object> metadata = new LinkedHashMap<>();
    metadata.put("title", "New Series Title");
    metadata.put("doesNotExist", "value");
    stubArguments(metadata, null);

    // updateAllSeriesMetadata is not expected, so calling it fails the test
    EasyMock.replay(bundleContext, index, indexService, seriesService, environment);

    GraphQLRuntimeException e = assertThrows(GraphQLRuntimeException.class, () -> buildCommand().execute());
    assertEquals(OpencastErrorType.BadRequest, e.getErrorType());
    assertTrue(e.getMessage().contains("doesNotExist"));

    EasyMock.verify(index, indexService, seriesService);
  }

  @Test
  void buildFailsWhenSeriesIdIsNull() {
    assertThrows(IllegalStateException.class, () -> UpdateSeriesCommand
        .create(null, new GqlCommonSeriesMetadataInput())
        .environment(environment)
        .build());
  }

  @Test
  void buildFailsWhenSeriesIdIsEmpty() {
    assertThrows(IllegalStateException.class, () -> UpdateSeriesCommand
        .create("", new GqlCommonSeriesMetadataInput())
        .environment(environment)
        .build());
  }

  @Test
  void buildFailsWhenMetadataInputIsNull() {
    assertThrows(IllegalStateException.class, () -> UpdateSeriesCommand
        .create(SERIES_ID, null)
        .environment(environment)
        .build());
  }

  @Test
  void buildFailsWhenEnvironmentIsMissing() {
    assertThrows(IllegalStateException.class, () -> UpdateSeriesCommand
        .create(SERIES_ID, new GqlCommonSeriesMetadataInput())
        .build());
  }

  private void assertMetadataUpdateFailureIsMapped(Exception thrown, Class<? extends Throwable> expected)
          throws Exception {
    stubArguments(new LinkedHashMap<>(), null);
    EasyMock.expect(indexService.updateAllSeriesMetadata(
        EasyMock.eq(SERIES_ID), EasyMock.anyObject(MetadataList.class), EasyMock.eq(index))).andThrow(thrown);

    EasyMock.replay(bundleContext, index, indexService, seriesService, environment);

    assertThrows(expected, () -> buildCommand().execute());

    EasyMock.verify(index, indexService, seriesService, environment);
  }

  private AbstractCommand<GqlSeries> buildCommand() {
    return UpdateSeriesCommand.create(SERIES_ID, new GqlCommonSeriesMetadataInput())
        .environment(environment)
        .build();
  }

  private void stubArguments(Map<String, Object> metadata, Map<String, Object> acl) {
    EasyMock.expect(environment.getArgument("metadata")).andReturn(metadata);
    // Only reached when updating the metadata does not throw, so tolerate zero invocations too.
    EasyMock.expect(environment.getArgument("acl")).andReturn(acl).anyTimes();
  }

}
