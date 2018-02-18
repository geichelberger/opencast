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

package org.opencastproject.index.service.resources.list.impl;

import static org.opencastproject.index.service.util.ListProviderUtil.invertMap;

import org.opencastproject.index.service.exception.ListProviderException;
import org.opencastproject.index.service.resources.list.api.ListProvidersService;
import org.opencastproject.index.service.resources.list.api.ResourceListProvider;
import org.opencastproject.index.service.resources.list.api.ResourceListQuery;
import org.opencastproject.index.service.util.ListProviderUtil;
import org.opencastproject.scheduler.api.SchedulerService;
import org.opencastproject.scheduler.api.SchedulerService.ReviewStatus;
import org.opencastproject.security.api.Organization;
import org.opencastproject.workflow.api.WorkflowInstance;
import org.opencastproject.workflow.api.WorkflowInstance.WorkflowState;

import org.osgi.framework.BundleContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class ListProvidersServiceImpl implements ListProvidersService {

  private static final Logger logger = LoggerFactory.getLogger(ListProvidersServiceImpl.class);
  private static final String FILTER_SUFFIX = "Filter";

  public static final String REVIEW_STATUS = "review_status";

  private Map<String, ResourceListProvider> providers = new ConcurrentHashMap<String, ResourceListProvider>();

  /** OSGi callback for provider. */
  public void addProvider(ResourceListProvider provider) {
    for (String listName : provider.getListNames()) {
      addProvider(listName, provider);
    }
  }

  /** OSGi callback for provider. */
  public void removeProvider(ResourceListProvider provider) {
    for (String listName : provider.getListNames()) {
      removeProvider(listName);
    }
  }

  public void activate(BundleContext bundleContext) {
    addCountries();
    addWorkflowStatus();
    addReviewStatus();

    logger.info("Activate the list provider");
  }

  // ====================================
  // Workflow status
  // ====================================

  private void addWorkflowStatus() {
    final String[] title = new String[] { "recording_states" };
    final Map<String, String> workflowStatus = new HashMap<String, String>();

    for (WorkflowState s : WorkflowInstance.WorkflowState.values()) {
      workflowStatus.put(s.name(), "EVENTS.EVENT.TABLE.FILTER.STATUS." + s.name());
    }

    providers.put(title[0], new ResourceListProvider() {

      @Override
      public String[] getListNames() {
        return title;
      }

      @Override
      public Map<String, String> getList(String listName, ResourceListQuery query, Organization organization) {
        return ListProviderUtil.filterMap(workflowStatus, query);

      }

      @Override
      public boolean isTranslatable(String listName) {
        return true;
      }

      @Override
      public String getDefault() {
        return null;
      }
    });
  }

  // ====================================
  // Event review status
  // ====================================

  private void addReviewStatus() {

    final String[] title = new String[] { REVIEW_STATUS };
    final Map<String, String> workflowStatus = new HashMap<String, String>();

    for (ReviewStatus s : SchedulerService.ReviewStatus.values()) {
      workflowStatus.put(s.name(), "FILTERS.EVENTS.REVIEW_STATUS." + s.name());
    }

    providers.put(title[0], new ResourceListProvider() {

      @Override
      public String[] getListNames() {
        return title;
      }

      @Override
      public Map<String, String> getList(String listName, ResourceListQuery query, Organization organization) {
        return ListProviderUtil.filterMap(workflowStatus, query);

      }

      @Override
      public boolean isTranslatable(String listName) {
        return true;
      }

      @Override
      public String getDefault() {
        return null;
      }
    });
  }

  // ====================================
  // Countries
  // ====================================

  private void addCountries() {
    final String[] title = new String[] { "countries" };
    String[] countriesISO = Locale.getISOCountries();
    final Map<String, String> countries = new HashMap<String, String>();
    for (String countryCode : countriesISO) {
      Locale obj = new Locale("", countryCode);
      countries.put(obj.getCountry(), obj.getDisplayCountry());
    }

    providers.put(title[0], new ResourceListProvider() {

      @Override
      public String[] getListNames() {
        return title;
      }

      @Override
      public Map<String, String> getList(String listName, ResourceListQuery query, Organization organization) {
        return ListProviderUtil.filterMap(countries, query);
      }


      @Override
      public boolean isTranslatable(String listName) {
        return true;
      }

      @Override
      public String getDefault() {
        return null;
      }
    });
  }

  @Override
  public Map<String, String> getList(String listName, ResourceListQuery query, Organization organization,
          boolean inverseValueKey) throws ListProviderException {
    ResourceListProvider provider = providers.get(listName);
    if (provider == null)
      throw new ListProviderException("No resources list found with the name " + listName);
    Map<String, String> list = provider.getList(listName, query, organization);
    if (inverseValueKey) {
      list = invertMap(list);
    }

    return list;
  }

  @Override
  public boolean isTranslatable(String listName) throws ListProviderException {
    ResourceListProvider provider = providers.get(listName);
    if (provider == null)
      throw new ListProviderException("No resources list found with the name " + listName);
    return provider.isTranslatable(listName);
  }

  @Override
  public String getDefault(String listName) throws ListProviderException {
    ResourceListProvider provider = providers.get(listName);
    if (provider == null)
      throw new ListProviderException("No resources list found with the name " + listName);
    return provider.getDefault();
  }

  @Override
  public void addProvider(String listName, ResourceListProvider provider) {
    providers.put(listName, provider);
  }

  @Override
  public void removeProvider(String name) {
    providers.remove(name);
  }

  @Override
  public boolean hasProvider(String name) {
    return providers.containsKey(name);
  }

  @Override
  public List<String> getAvailableProviders() {
    return new ArrayList<String>(providers.keySet());
  }
}
