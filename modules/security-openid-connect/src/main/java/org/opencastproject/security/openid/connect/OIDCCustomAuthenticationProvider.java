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
import com.nimbusds.jwt.JWT;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collection;

public class OIDCCustomAuthenticationProvider implements AuthenticationProvider {

  /** The logging facility */
  private static final Logger logger = LoggerFactory.getLogger(OIDCCustomAuthenticationProvider.class);

  private final UserInfoFetcher userInfoFetcher = new UserInfoFetcher();

  public OidcAuthoritiesMapper getAuthoritiesMapper() {
    return authoritiesMapper;
  }

  public void setAuthoritiesMapper(OidcAuthoritiesMapper authoritiesMapper) {
    this.authoritiesMapper = authoritiesMapper;
  }

  private OidcAuthoritiesMapper authoritiesMapper;

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    if (!supports(authentication.getClass())) {
      return null;
    }

    if (authentication instanceof PendingOIDCAuthenticationToken) {

      PendingOIDCAuthenticationToken token = (PendingOIDCAuthenticationToken) authentication;

      // get the ID Token value out
      JWT idToken = token.getIdToken();

      // load the user info if we can
      UserInfo userInfo = userInfoFetcher.loadUserInfo(token);

      if (userInfo == null) {
        // user info not found -- could be an error, could be fine
      } else {
        // if we found userinfo, double check it
        if (!Strings.isNullOrEmpty(userInfo.getSubject().toString()) && !userInfo.getSubject().getValue()
            .equals(token.getSub())) {
          // the userinfo came back and the user_id fields don't match what was in the id_token
          throw new UsernameNotFoundException("user_id mismatch between id_token and user_info call: "
              + token.getSub() + " / " + userInfo.getSubject());
        }
      }

      return createAuthenticationToken(token, authoritiesMapper.mapAuthorities(idToken, userInfo), userInfo);
    }

    return null;
  }

  protected Authentication createAuthenticationToken(PendingOIDCAuthenticationToken token,
      Collection<? extends GrantedAuthority> authorities, UserInfo userInfo) {
    return new OIDCAuthenticationToken(token.getSub(),
        token.getIssuer(),
        userInfo, authorities,
        token.getIdToken(), token.getAccessTokenValue(), token.getRefreshTokenValue());
  }

  @Override
  public boolean supports(Class<?> aClass) {
    return false;
  }
}
