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

import com.nimbusds.jwt.JWT;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public interface OidcAuthoritiesMapper {

  /**
   * @param idToken the ID Token (parsed as a JWT, cannot be @null)
   * @param userInfo userInfo of the current user (could be @null)
   * @return the set of authorities to map to this user
   */
  Collection<? extends GrantedAuthority> mapAuthorities(JWT idToken, UserInfo userInfo);

}
