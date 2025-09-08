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

import org.opencastproject.security.api.Organization;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.security.api.UserDirectoryService;
import org.opencastproject.security.impl.jpa.JpaOrganization;
import org.opencastproject.security.impl.jpa.JpaRole;
import org.opencastproject.security.impl.jpa.JpaUserReference;
import org.opencastproject.userdirectory.api.UserReferenceProvider;

import org.mitre.openid.connect.model.UserInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

public class CustomUserInfoHandler implements UserInfoHandler {

  /** The logging facility */
  private static final Logger logger = LoggerFactory.getLogger(OIDCCustomAuthenticationProvider.class);

  private UserReferenceProvider userReferenceProvider;

  private UserDetailsService userDetailsService;

  private SecurityService securityService;

  private UserDirectoryService userDirectoryService;

  private final String roleUserPrefix = "ROLE_OIDC_USER_";

  /**
   * Handles add and update user
   *
   * @param userInfo
   * @param authorities
   */
  public void handle(UserInfo userInfo, Collection<? extends GrantedAuthority> authorities) {
    try {
      if (userDetailsService.loadUserByUsername(userInfo.getSub()) != null) {
        updateUserReference(userInfo);
      }
    } catch (UsernameNotFoundException e) {
      newUser(userInfo, authorities);
      userDirectoryService.invalidate(userInfo.getSub());
    }
  }

  /**
   * Update user info
   *
   * @param userInfo User info retrieved from openid connect auth server
   */
  protected void updateUserReference(UserInfo userInfo) {
    Organization organization = securityService.getOrganization();

    JpaUserReference userReference = userReferenceProvider.findUserReference(userInfo.getSub(),organization.getId());
    if (userReference == null) {
      throw new IllegalStateException("User reference '" + userInfo.getSub() + "' was not found");
    }

    userReference.setName(userInfo.getName());
    userReference.setEmail(userInfo.getEmail());
    userReference.setLastLogin(new Date());

    userReferenceProvider.updateUserReference(userReference);
  }

  /**
   * Adds new user
   *
   * @param userInfo User info retrieved from openid connect auth server
   * @param authorities Authorities set by AuthoritiesMapper
   */
  protected void newUser(UserInfo userInfo, Collection<? extends GrantedAuthority> authorities) {
    JpaOrganization organization = fromOrganization(securityService.getOrganization());
    Set<JpaRole> roles = extractRoles(userInfo, authorities);

    JpaUserReference userReference = new JpaUserReference(userInfo.getSub(), userInfo.getName(),
            userInfo.getEmail(), "openid-connect", new Date(), organization, roles);

    logger.debug("OpenID Connect user '{}' logged in for the first time", userInfo.getSub());
    userReferenceProvider.addUserReference(userReference, "openid-connect");
  }

  public void setUserReferenceProvider(UserReferenceProvider userReferenceProvider) {
    this.userReferenceProvider = userReferenceProvider;
  }

  public void setUserDetailsService(UserDetailsService userDetailsService) {
    this.userDetailsService = userDetailsService;
  }

  public void setSecurityService(SecurityService securityService) {
    this.securityService = securityService;
  }

  /**
   * Creates a JpaOrganization from an organization
   *
   * @param org
   *          the organization
   */
  private JpaOrganization fromOrganization(Organization org) {
    if (org instanceof JpaOrganization) {
      return (JpaOrganization) org;
    } else {
      return new JpaOrganization(org.getId(), org.getName(), org.getServers(), org.getAdminRole(),
              org.getAnonymousRole(), org.getProperties());
    }
  }

  /**
   * Extract JpaRoles from GrantedAuthorities
   */
  private Set<JpaRole> extractRoles(UserInfo userInfo,Collection<? extends GrantedAuthority> authorities) {
    JpaOrganization organization = fromOrganization(securityService.getOrganization());
    Set<JpaRole> roles = new HashSet<>();
    roles.add(new JpaRole(roleUserPrefix + userInfo.getSub().toUpperCase(), organization));
    return roles;
  }

  public void setUserDirectoryService(UserDirectoryService userDirectoryService) {
    this.userDirectoryService = userDirectoryService;
  }
}
