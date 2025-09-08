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

import org.mitre.openid.connect.client.OIDCAuthenticationProvider;
import org.mitre.openid.connect.model.PendingOIDCAuthenticationToken;
import org.mitre.openid.connect.model.UserInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.util.Collection;

public class OIDCCustomAuthenticationProvider extends OIDCAuthenticationProvider {

  /** The logging facility */
  private static final Logger logger = LoggerFactory.getLogger(OIDCCustomAuthenticationProvider.class);

  @Override
  protected Authentication createAuthenticationToken(PendingOIDCAuthenticationToken token,
          Collection<? extends GrantedAuthority> authorities, UserInfo userInfo) {
    UserDetails userDetails = new User(token.getSub(), "", true, true, true, true, authorities);
    return new PreAuthenticatedAuthenticationToken(userDetails, token.getAccessTokenValue(), authorities);
  }

}
