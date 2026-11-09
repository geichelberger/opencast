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

import org.opencastproject.authorization.xacml.manager.api.AclService;
import org.opencastproject.authorization.xacml.manager.api.AclServiceFactory;
import org.opencastproject.authorization.xacml.manager.api.ManagedAcl;
import org.opencastproject.elasticsearch.api.SearchIndexException;
import org.opencastproject.elasticsearch.index.ElasticsearchIndex;
import org.opencastproject.elasticsearch.index.objects.series.Series;
import org.opencastproject.graphql.exception.GraphQLNotFoundException;
import org.opencastproject.graphql.exception.GraphQLRuntimeException;
import org.opencastproject.graphql.exception.GraphQLUnauthorizedException;
import org.opencastproject.graphql.exception.OpencastErrorType;
import org.opencastproject.graphql.series.GqlSeries;
import org.opencastproject.security.api.AccessControlEntry;
import org.opencastproject.security.api.AccessControlList;
import org.opencastproject.security.api.Organization;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.security.api.UnauthorizedException;
import org.opencastproject.security.api.User;
import org.opencastproject.series.api.SeriesException;
import org.opencastproject.series.api.SeriesService;
import org.opencastproject.util.NotFoundException;

import org.easymock.Capture;
import org.easymock.EasyMock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public class UpdateSeriesAclCommandTest extends AbstractCommandTest {

  private static final String SERIES_ID = "series-1";
  private static final String ORG_ID = "mh_default_org";

  private ElasticsearchIndex index;
  private SeriesService seriesService;
  private Organization organization;
  private User user;

  @BeforeEach
  void setUp() {
    index = EasyMock.createMock(ElasticsearchIndex.class);
    seriesService = EasyMock.createMock(SeriesService.class);
    organization = EasyMock.createNiceMock(Organization.class);
    EasyMock.expect(organization.getId()).andReturn(ORG_ID).anyTimes();
    user = EasyMock.createNiceMock(User.class);
    EasyMock.replay(organization, user);
    context.setOrganization(organization);
    context.setUser(user);

    mockService(ElasticsearchIndex.class, index);
    mockService(SeriesService.class, seriesService);
  }

  @Test
  void updatesAclAndReturnsSeries() throws Exception {
    stubAclArgument(aclArgument(null, "ROLE_USER", "read", "write"));

    Capture<AccessControlList> capturedAcl = Capture.newInstance();
    EasyMock.expect(seriesService.updateAccessControl(EasyMock.eq(SERIES_ID), EasyMock.capture(capturedAcl)))
        .andReturn(true);
    Series series = new Series(SERIES_ID, ORG_ID);
    series.setTitle("Series Title");
    EasyMock.expect(index.getSeries(SERIES_ID, organization, user)).andReturn(Optional.of(series));

    EasyMock.replay(bundleContext, index, seriesService, environment);

    GqlSeries result = buildCommand().execute();

    assertEquals(SERIES_ID, result.id());
    assertEquals("Series Title", result.title());
    Set<String> entries = capturedAcl.getValue().getEntries().stream()
        .map(e -> e.getRole() + ":" + e.getAction())
        .collect(Collectors.toSet());
    assertEquals(Set.of("ROLE_USER:read", "ROLE_USER:write"), entries);

    EasyMock.verify(index, seriesService, environment);
  }

  @Test
  void mergesManagedAclWithExplicitEntries() throws Exception {
    AclServiceFactory aclServiceFactory = EasyMock.createMock(AclServiceFactory.class);
    SecurityService securityService = EasyMock.createMock(SecurityService.class);
    AclService aclService = EasyMock.createMock(AclService.class);
    ManagedAcl managedAcl = EasyMock.createMock(ManagedAcl.class);
    mockService(AclServiceFactory.class, aclServiceFactory);
    mockService(SecurityService.class, securityService);

    stubAclArgument(aclArgument(3L, "ROLE_USER", "read"));

    EasyMock.expect(securityService.getOrganization()).andReturn(organization);
    EasyMock.expect(aclServiceFactory.serviceFor(organization)).andReturn(aclService);
    EasyMock.expect(aclService.getAcl(3L)).andReturn(Optional.of(managedAcl));
    EasyMock.expect(managedAcl.getAcl())
        .andReturn(new AccessControlList(new AccessControlEntry("ROLE_ADMIN", "write", true)));

    Capture<AccessControlList> capturedAcl = Capture.newInstance();
    EasyMock.expect(seriesService.updateAccessControl(EasyMock.eq(SERIES_ID), EasyMock.capture(capturedAcl)))
        .andReturn(true);
    EasyMock.expect(index.getSeries(SERIES_ID, organization, user))
        .andReturn(Optional.of(new Series(SERIES_ID, ORG_ID)));

    EasyMock.replay(bundleContext, index, seriesService, environment, aclServiceFactory, securityService,
        aclService, managedAcl);

    buildCommand().execute();

    Set<String> entries = capturedAcl.getValue().getEntries().stream()
        .map(e -> e.getRole() + ":" + e.getAction())
        .collect(Collectors.toSet());
    assertEquals(Set.of("ROLE_USER:read", "ROLE_ADMIN:write"), entries);

    EasyMock.verify(index, seriesService, environment, aclServiceFactory, securityService, aclService,
        managedAcl);
  }

  @Test
  void failsWhenNoAclIsGiven() throws Exception {
    stubAclArgument(null);

    // seriesService has no expectations, so any call to it fails the test
    EasyMock.replay(bundleContext, index, seriesService, environment);

    GraphQLRuntimeException e = assertThrows(GraphQLRuntimeException.class, () -> buildCommand().execute());
    assertEquals(OpencastErrorType.BadRequest, e.getErrorType());
    EasyMock.verify(index, seriesService, environment);
  }

  @Test
  void rejectsAclArgumentThatCannotBeRead() throws Exception {
    stubAclArgument(Map.of("entries", "not a list"));

    EasyMock.replay(bundleContext, index, seriesService, environment);

    GraphQLRuntimeException e = assertThrows(GraphQLRuntimeException.class, () -> buildCommand().execute());
    assertEquals(OpencastErrorType.BadRequest, e.getErrorType());
    assertEquals("Invalid value for argument 'acl'", e.getMessage());
    EasyMock.verify(index, seriesService, environment);
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
  void wrapsSeriesExceptionAsGraphQLRuntimeException() throws Exception {
    assertAclUpdateFailureIsMapped(new SeriesException("boom"), GraphQLRuntimeException.class);
  }

  @Test
  void failsSoftWhenSeriesIsNotIndexedAfterAclUpdate() throws Exception {
    stubAclArgument(aclArgument(null, "ROLE_USER", "read"));
    EasyMock.expect(seriesService.updateAccessControl(EasyMock.eq(SERIES_ID), EasyMock.anyObject()))
        .andReturn(true);
    EasyMock.expect(index.getSeries(SERIES_ID, organization, user)).andReturn(Optional.empty());

    EasyMock.replay(bundleContext, index, seriesService, environment);

    assertThrows(GraphQLRuntimeException.class, () -> buildCommand().execute());

    EasyMock.verify(index, seriesService, environment);
  }

  @Test
  void wrapsSearchIndexExceptionWhileLoadingSeries() throws Exception {
    stubAclArgument(aclArgument(null, "ROLE_USER", "read"));
    EasyMock.expect(seriesService.updateAccessControl(EasyMock.eq(SERIES_ID), EasyMock.anyObject()))
        .andReturn(true);
    EasyMock.expect(index.getSeries(SERIES_ID, organization, user)).andThrow(new SearchIndexException("boom"));

    EasyMock.replay(bundleContext, index, seriesService, environment);

    assertThrows(GraphQLRuntimeException.class, () -> buildCommand().execute());

    EasyMock.verify(index, seriesService, environment);
  }

  @Test
  void buildFailsWhenSeriesIdIsNull() {
    assertThrows(IllegalStateException.class, () -> UpdateSeriesAclCommand.create(null)
        .environment(environment)
        .build());
  }

  @Test
  void buildFailsWhenSeriesIdIsEmpty() {
    assertThrows(IllegalStateException.class, () -> UpdateSeriesAclCommand.create("")
        .environment(environment)
        .build());
  }

  @Test
  void buildFailsWhenEnvironmentIsMissing() {
    assertThrows(IllegalStateException.class, () -> UpdateSeriesAclCommand.create(SERIES_ID).build());
  }

  private void assertAclUpdateFailureIsMapped(Exception thrown, Class<? extends Throwable> expected)
          throws Exception {
    stubAclArgument(aclArgument(null, "ROLE_USER", "read"));
    EasyMock.expect(seriesService.updateAccessControl(EasyMock.eq(SERIES_ID), EasyMock.anyObject()))
        .andThrow(thrown);

    EasyMock.replay(bundleContext, index, seriesService, environment);

    assertThrows(expected, () -> buildCommand().execute());

    EasyMock.verify(index, seriesService, environment);
  }

  private AbstractCommand<GqlSeries> buildCommand() {
    return UpdateSeriesAclCommand.create(SERIES_ID).environment(environment).build();
  }

  private void stubAclArgument(Map<String, Object> acl) {
    EasyMock.expect(environment.getArgument("acl")).andReturn(acl);
  }

}
