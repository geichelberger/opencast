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
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import org.easymock.EasyMock;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;

public class DefaultAuthoritiesMapperTest {

  private DefaultAuthoritiesMapper defaultAuthoritiesMapper;

  @Before
  public void setUp() throws Exception {
    UserInfoHandler userInfoHandler = EasyMock.createMock(UserInfoHandler.class);
    defaultAuthoritiesMapper = new DefaultAuthoritiesMapper();
    defaultAuthoritiesMapper.setUserInfoHandler(userInfoHandler);
  }

  @Test
  public void mapAuthorities() throws Exception {
    JWTClaimsSet jwtClaimsSet = (new JWTClaimsSet.Builder()).subject("test_subject").issuer("http://test_issuer")
        .build();
    JWT jwt = new PlainJWT(jwtClaimsSet);
    UserInfo userInfo = new UserInfo(jwtClaimsSet);

    Collection<? extends GrantedAuthority> collection =  defaultAuthoritiesMapper.mapAuthorities(jwt, userInfo);
    Assert.assertNotNull(collection);
    Assert.assertTrue(collection.contains(new SimpleGrantedAuthority("ROLE_ANONYMOUS")));
  }


}
