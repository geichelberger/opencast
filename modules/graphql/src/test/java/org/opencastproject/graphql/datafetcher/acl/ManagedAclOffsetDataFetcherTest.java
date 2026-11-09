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

package org.opencastproject.graphql.datafetcher.acl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.opencastproject.authorization.xacml.manager.api.AclService;
import org.opencastproject.authorization.xacml.manager.api.AclServiceFactory;
import org.opencastproject.authorization.xacml.manager.api.ManagedAcl;
import org.opencastproject.graphql.acl.GqlManagedAclCatalogue;
import org.opencastproject.graphql.datafetcher.ParameterDataFetcher;
import org.opencastproject.graphql.exception.GraphQLRuntimeException;
import org.opencastproject.graphql.exception.OpencastErrorType;
import org.opencastproject.graphql.execution.context.OpencastContext;
import org.opencastproject.graphql.execution.context.OpencastContextManager;
import org.opencastproject.security.api.DefaultOrganization;
import org.opencastproject.security.api.Organization;
import org.opencastproject.security.api.SecurityService;

import org.easymock.EasyMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;

import java.util.ArrayList;
import java.util.List;

import graphql.schema.DataFetchingEnvironment;

class ManagedAclOffsetDataFetcherTest {

  private static final int ACL_COUNT = 5;

  private OpencastContext context;

  @BeforeEach
  @SuppressWarnings("unchecked")
  void setUp() {
    Organization organization = new DefaultOrganization();

    List<ManagedAcl> acls = new ArrayList<>();
    for (int i = 0; i < ACL_COUNT; i++) {
      ManagedAcl acl = EasyMock.createNiceMock(ManagedAcl.class);
      EasyMock.expect(acl.getName()).andReturn("acl " + i).anyTimes();
      EasyMock.replay(acl);
      acls.add(acl);
    }
    AclService aclService = EasyMock.createMock(AclService.class);
    EasyMock.expect(aclService.getAcls()).andReturn(acls).anyTimes();
    AclServiceFactory aclServiceFactory = EasyMock.createMock(AclServiceFactory.class);
    EasyMock.expect(aclServiceFactory.serviceFor(organization)).andReturn(aclService).anyTimes();
    SecurityService securityService = EasyMock.createMock(SecurityService.class);
    EasyMock.expect(securityService.getOrganization()).andReturn(organization).anyTimes();

    BundleContext bundleContext = EasyMock.createMock(BundleContext.class);
    ServiceReference<AclServiceFactory> factoryReference = EasyMock.createMock(ServiceReference.class);
    ServiceReference<SecurityService> securityReference = EasyMock.createMock(ServiceReference.class);
    EasyMock.expect(bundleContext.getServiceReference(AclServiceFactory.class)).andReturn(factoryReference)
        .anyTimes();
    EasyMock.expect(bundleContext.getService(factoryReference)).andReturn(aclServiceFactory).anyTimes();
    EasyMock.expect(bundleContext.getServiceReference(SecurityService.class)).andReturn(securityReference)
        .anyTimes();
    EasyMock.expect(bundleContext.getService(securityReference)).andReturn(securityService).anyTimes();
    EasyMock.replay(aclService, aclServiceFactory, securityService, bundleContext);

    context = OpencastContextManager.initiateContext(bundleContext);
  }

  @AfterEach
  void tearDown() {
    OpencastContextManager.clearContext();
  }

  @Test
  void returnsRequestedPageWithTotalCount() {
    GqlManagedAclCatalogue result = new ManagedAclOffsetDataFetcher().get(context, arguments(2, 1));

    assertEquals(ACL_COUNT, result.totalCount());
    assertEquals(2, result.nodes().size());
    assertEquals(3L, result.pageInfo().pageCount());
  }

  @Test
  void returnsAllAclsWithinTheDefaultPageSize() {
    GqlManagedAclCatalogue result = new ManagedAclOffsetDataFetcher().get(context, arguments(null, null));

    assertEquals(ACL_COUNT, result.totalCount());
    assertEquals(ACL_COUNT, result.nodes().size());
  }

  @Test
  void rejectsInvalidPaging() {
    for (int limit : new int[] { 0, -1, ParameterDataFetcher.MAX_PAGE_SIZE + 1 }) {
      GraphQLRuntimeException e = assertThrows(GraphQLRuntimeException.class,
          () -> new ManagedAclOffsetDataFetcher().get(context, arguments(limit, 0)));
      assertEquals(OpencastErrorType.BadRequest, e.getErrorType(), "limit " + limit);
    }
    GraphQLRuntimeException e = assertThrows(GraphQLRuntimeException.class,
        () -> new ManagedAclOffsetDataFetcher().get(context, arguments(10, -1)));
    assertEquals(OpencastErrorType.BadRequest, e.getErrorType());
  }

  private static DataFetchingEnvironment arguments(Integer limit, Integer offset) {
    DataFetchingEnvironment env = EasyMock.createNiceMock(DataFetchingEnvironment.class);
    EasyMock.expect(env.getArgument("limit")).andReturn(limit).anyTimes();
    EasyMock.expect(env.getArgument("offset")).andReturn(offset).anyTimes();
    EasyMock.replay(env);
    return env;
  }

}
