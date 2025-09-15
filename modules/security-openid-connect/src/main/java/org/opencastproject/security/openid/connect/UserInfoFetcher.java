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

import com.google.common.base.Strings;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.UncheckedExecutionException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

public class UserInfoFetcher {

  /**
   * Logger for this class
   */
  private static final Logger logger = LoggerFactory.getLogger(UserInfoFetcher.class);

  private LoadingCache<PendingOIDCAuthenticationToken, UserInfo> cache;

  public UserInfoFetcher() {
    cache = CacheBuilder.newBuilder()
        .expireAfterWrite(1, TimeUnit.HOURS) // expires 1 hour after fetch
        .maximumSize(100)
        .build(new UserInfoLoader());
  }

  public UserInfo loadUserInfo(final PendingOIDCAuthenticationToken token) {
    try {
      return cache.get(token);
    } catch (UncheckedExecutionException | ExecutionException e) {
      logger.warn("Couldn't load User Info from token: " + e.getMessage());
      return null;
    }

  }


  private class UserInfoLoader extends CacheLoader<PendingOIDCAuthenticationToken, UserInfo> {

    UserInfoLoader() {
    }

    @Override
    public UserInfo load(final PendingOIDCAuthenticationToken token) throws URISyntaxException {


      OIDCProviderMetadata serverConfiguration = token.getServerConfiguration();

      if (serverConfiguration == null) {
        logger.warn("No server configuration found.");
        return null;
      }

      if (Strings.isNullOrEmpty(String.valueOf(serverConfiguration.getUserInfoEndpointURI()))) {
        logger.warn("No userinfo endpoint, not fetching.");
        return null;
      }

      UserInfoResponse userInfoResponse = null;

      BearerAccessToken accessToken = new BearerAccessToken(token.getRefreshTokenValue());

      try {
        HTTPResponse httpResponse = new UserInfoRequest(serverConfiguration.getUserInfoEndpointURI(),
            accessToken).toHTTPRequest().send();
        userInfoResponse = UserInfoResponse.parse(httpResponse);

      } catch (IOException e) {

      } catch (ParseException e) {
        throw new RuntimeException(e);
      }

      assert userInfoResponse != null;

      if (!userInfoResponse.indicatesSuccess()) {
        logger.warn("Userinfo response was not successful.");
        return null;
      }

      UserInfo userInfo = userInfoResponse.toSuccessResponse().getUserInfo();
      return userInfo;
    }
  }

}
