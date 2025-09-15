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
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.text.ParseException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

public class NamedAdminAuthoritiesMapper implements OidcAuthoritiesMapper {

  private static Logger logger = LoggerFactory.getLogger(NamedAdminAuthoritiesMapper.class);

  private static final SimpleGrantedAuthority ROLE_ADMIN = new SimpleGrantedAuthority("ROLE_ADMIN");
  private static final SimpleGrantedAuthority ROLE_USER = new SimpleGrantedAuthority("ROLE_USER");

  private Set<SubjectIssuerGrantedAuthority> admins = new HashSet<>();

  @Override
  public Collection<? extends GrantedAuthority> mapAuthorities(JWT idToken, UserInfo userInfo) {

    Set<GrantedAuthority> out = new HashSet<>();
    try {
      JWTClaimsSet claims = idToken.getJWTClaimsSet();

      SubjectIssuerGrantedAuthority authority = new SubjectIssuerGrantedAuthority(claims.getSubject(),
          claims.getIssuer());
      out.add(authority);

      if (admins.contains(authority)) {
        out.add(ROLE_ADMIN);
      }

      // everybody's a user by default
      out.add(ROLE_USER);

    } catch (ParseException e) {
      logger.error("Unable to parse ID Token inside of authorities mapper (huh?)");
    }
    return out;
  }

  /**
   * @return the admins
   */
  public Set<SubjectIssuerGrantedAuthority> getAdmins() {
    return admins;
  }

  /**
   * @param admins the admins to set
   */
  public void setAdmins(Set<SubjectIssuerGrantedAuthority> admins) {
    this.admins = admins;
  }

}
