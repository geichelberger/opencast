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

import static org.hamcrest.Matchers.instanceOf;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mitre.openid.connect.model.DefaultUserInfo;
import org.mitre.openid.connect.model.PendingOIDCAuthenticationToken;
import org.mitre.openid.connect.model.UserInfo;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.HashSet;

public class OIDCCustomAuthenticationProviderTest {

  @Before
  public void setUp() throws Exception {
  }

  @Test
  public void createAuthenticationToken() throws Exception {
    OIDCCustomAuthenticationProvider customAuthenticationProvider = new OIDCCustomAuthenticationProvider();

    PendingOIDCAuthenticationToken pendingOIDCAuthenticationToken = new PendingOIDCAuthenticationToken("test_subject",
            "http://test_auth", null, null, "test_access_token", null);

    Collection<GrantedAuthority> authorities = new HashSet<>();
    authorities.add((GrantedAuthority) () -> "test_authority");

    UserInfo userInfo = new DefaultUserInfo();

    Authentication authentication = customAuthenticationProvider
            .createAuthenticationToken(pendingOIDCAuthenticationToken, authorities, userInfo);

    Assert.assertThat(authentication.getPrincipal(), instanceOf(UserDetails.class));
    Assert.assertEquals("test_subject", ((UserDetails) authentication.getPrincipal()).getUsername());
    Assert.assertEquals(authorities.size(), authentication.getAuthorities().size());
  }

}
