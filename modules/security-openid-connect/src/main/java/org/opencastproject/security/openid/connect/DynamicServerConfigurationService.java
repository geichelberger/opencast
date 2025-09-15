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

package org.opencastproject.security.openid.connect;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.UncheckedExecutionException;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationServiceException;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutionException;

public class DynamicServerConfigurationService {

  /**
   * Logger for this class
   */
  private static final Logger logger = LoggerFactory.getLogger(DynamicServerConfigurationService.class);

  private LoadingCache<Issuer, OIDCProviderMetadata> servers;

  private Set<Issuer> whitelist = new HashSet<>();
  private Set<Issuer> blacklist = new HashSet<>();

  public DynamicServerConfigurationService() {
    servers = CacheBuilder.newBuilder().build(new OpenIDConnectServiceConfigurationFetcher());
  }

  /**
   * @return the whitelist
   */
  public Set<Issuer> getWhitelist() {
    return whitelist;
  }

  /**
   * @param whitelist the whitelist to set
   */
  public void setWhitelist(Set<Issuer> whitelist) {
    this.whitelist = whitelist;
  }

  /**
   * @return the blacklist
   */
  public Set<Issuer> getBlacklist() {
    return blacklist;
  }

  /**
   * @param blacklist the blacklist to set
   */
  public void setBlacklist(Set<Issuer> blacklist) {
    this.blacklist = blacklist;
  }

  /**
   * Get the server configuration for the given issuer. This will attempt to load the configuration from the issuer's
   * .well-known URL if it is not already cached.
   *
   * @param issuer
   *          The issuer URL
   * @return The server configuration, or null if it could not be loaded
   */
  public OIDCProviderMetadata getServerConfiguration(Issuer issuer) {
    try {

      if (!whitelist.isEmpty() && !whitelist.contains(issuer)) {
        throw new AuthenticationServiceException("Whitelist was nonempty, issuer was not in whitelist: " + issuer);
      }

      if (blacklist.contains(issuer)) {
        throw new AuthenticationServiceException("Issuer was in blacklist: " + issuer);
      }

      return servers.get(issuer);
    } catch (UncheckedExecutionException | ExecutionException e) {
      logger.warn("Couldn't load configuration for " + issuer + ": " + e);
      return null;
    }

  }

  private class OpenIDConnectServiceConfigurationFetcher extends CacheLoader<Issuer, OIDCProviderMetadata> {

    OpenIDConnectServiceConfigurationFetcher() {
    }

    @Override
    public OIDCProviderMetadata load(Issuer issuer) throws Exception {
      OIDCProviderMetadata providerMetadata = OIDCProviderMetadata.resolve(
          issuer,
          1000,
          1000);

      return providerMetadata;
    }

  }

}
