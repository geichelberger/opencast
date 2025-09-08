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

import static org.easymock.EasyMock.anyObject;

import org.opencastproject.security.api.DefaultOrganization;
import org.opencastproject.security.api.Organization;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.security.api.UserDirectoryService;
import org.opencastproject.security.impl.jpa.JpaUserReference;
import org.opencastproject.userdirectory.api.UserReferenceProvider;

import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;
import org.mitre.openid.connect.model.DefaultUserInfo;
import org.mitre.openid.connect.model.UserInfo;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collection;
import java.util.HashSet;

public class CustomUserInfoHandlerTest {

  private CustomUserInfoHandler customUserInfoHandler;
  private UserInfo testUser;
  private UserInfo noUser;
  private Organization organization;

  private UserReferenceProvider userReferenceProvider;
  private UserDetailsService userDetailsService;
  private SecurityService securityService;

  @Before
  public void setUp() throws Exception {
    customUserInfoHandler = new CustomUserInfoHandler();

    noUser = new DefaultUserInfo();
    noUser.setSub("test-nouser");

    testUser = new DefaultUserInfo();
    testUser.setSub("test-subject");

    userReferenceProvider = EasyMock.createMock(UserReferenceProvider.class);

    userDetailsService = EasyMock.createNiceMock(UserDetailsService.class);

    UserDetails userDetails = new User(testUser.getSub(), "", new HashSet<GrantedAuthority>());
    EasyMock.expect(userDetailsService.loadUserByUsername(testUser.getSub())).andReturn(userDetails).anyTimes();
    EasyMock.expect(userDetailsService.loadUserByUsername(noUser.getSub()))
            .andThrow(new UsernameNotFoundException("test-nouser")).anyTimes();
    EasyMock.replay(userDetailsService);

    securityService = EasyMock.createMock(SecurityService.class);

    organization = new DefaultOrganization();

    EasyMock.expect(securityService.getOrganization()).andReturn(organization).anyTimes();
    EasyMock.replay(securityService);

    UserDirectoryService userDirectoryService = EasyMock.createMock(UserDirectoryService.class);

    customUserInfoHandler.setSecurityService(securityService);
    customUserInfoHandler.setUserDetailsService(userDetailsService);
    customUserInfoHandler.setUserDirectoryService(userDirectoryService);
    customUserInfoHandler.setUserReferenceProvider(userReferenceProvider);
  }

  @Test
  public void handleUpdateUser() throws Exception {

    EasyMock.expect(userReferenceProvider.findUserReference(testUser.getSub(), organization.getId()))
            .andReturn(new JpaUserReference());
    userReferenceProvider.updateUserReference(anyObject());
    EasyMock.expectLastCall();
    EasyMock.replay(userReferenceProvider);

    Collection<GrantedAuthority> authorities = new HashSet<>();
    customUserInfoHandler.handle(testUser, authorities);

    EasyMock.verify(userReferenceProvider);
  }

  @Test
  public void handleNewUser() throws Exception {

    userReferenceProvider.addUserReference(anyObject(), anyObject());
    EasyMock.expectLastCall();
    EasyMock.replay(userReferenceProvider);

    Collection<GrantedAuthority> authorities = new HashSet<>();
    customUserInfoHandler.handle(noUser, authorities);
    EasyMock.verify(securityService);
    EasyMock.verify(userReferenceProvider);
  }

}
