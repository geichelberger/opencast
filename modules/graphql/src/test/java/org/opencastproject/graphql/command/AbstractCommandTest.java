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

import org.opencastproject.graphql.execution.context.OpencastContext;
import org.opencastproject.graphql.execution.context.OpencastContextManager;
import org.opencastproject.index.service.catalog.adapter.ConfigurableDCCatalogUIAdapter;
import org.opencastproject.util.PropertiesUtil;

import org.easymock.EasyMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;

import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import graphql.schema.DataFetchingEnvironment;

/**
 * Shared setup for command tests: an {@link OpencastContext} backed by a mocked {@link BundleContext}, so that
 * services can be registered per test via {@link #mockService(Class, Object)}.
 */
abstract class AbstractCommandTest {

  protected BundleContext bundleContext;
  protected DataFetchingEnvironment environment;
  protected OpencastContext context;

  @BeforeEach
  void setUpContext() {
    bundleContext = EasyMock.createMock(BundleContext.class);
    environment = EasyMock.createMock(DataFetchingEnvironment.class);
    context = OpencastContextManager.initiateContext(bundleContext);
  }

  @AfterEach
  void tearDownContext() {
    OpencastContextManager.clearContext();
  }

  @SuppressWarnings("unchecked")
  protected <T> void mockService(Class<T> type, T service) {
    ServiceReference<T> reference = EasyMock.createMock(ServiceReference.class);
    EasyMock.expect(bundleContext.getServiceReference(type)).andReturn(reference).anyTimes();
    EasyMock.expect(bundleContext.getService(reference)).andReturn(service).anyTimes();
  }

  protected static Map<String, Object> aclArgument(Long managedAclId, String role, String... actions) {
    Map<String, Object> acl = new LinkedHashMap<>();
    if (managedAclId != null) {
      acl.put("managedAclId", managedAclId);
    }
    if (role == null) {
      acl.put("entries", List.of());
    } else {
      Map<String, Object> entry = new LinkedHashMap<>();
      entry.put("role", role);
      entry.put("action", List.of(actions));
      acl.put("entries", List.of(entry));
    }
    return acl;
  }

  protected static <T extends ConfigurableDCCatalogUIAdapter> T loadCatalogUIAdapter(T adapter, String resource)
          throws Exception {
    Properties properties = new Properties();
    try (InputStream in = AbstractCommandTest.class.getResourceAsStream(resource)) {
      properties.load(in);
    }
    adapter.updated(PropertiesUtil.toDictionary(properties));
    return adapter;
  }

}
