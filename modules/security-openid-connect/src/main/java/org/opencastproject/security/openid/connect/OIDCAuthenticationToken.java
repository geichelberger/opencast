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

import com.google.common.collect.ImmutableMap;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.text.ParseException;
import java.util.Collection;

public class OIDCAuthenticationToken extends AbstractAuthenticationToken {

  private static final long serialVersionUID = 22100073066377804L;

  private final ImmutableMap<String, String> principal;
  private final String accessTokenValue; // string representation of the access token
  private final String refreshTokenValue; // string representation of the refresh token
  private transient JWT idToken; // this needs a custom serializer
  private final String issuer; // issuer URL (parsed from the id token)
  private final String sub; // user id (parsed from the id token)

  private final UserInfo userInfo; // user info container

  /**
   * Constructs OIDCAuthenticationToken with a full set of authorities, marking this as authenticated.
   *
   * Set to authenticated.
   *
   * Constructs a Principal out of the subject and issuer.
   * @param subject
   * @param authorities
   * @param principal
   * @param idToken
   */
  public OIDCAuthenticationToken(String subject, String issuer,
      UserInfo userInfo, Collection<? extends GrantedAuthority> authorities,
      JWT idToken, String accessTokenValue, String refreshTokenValue) {

    super(authorities);

    this.principal = ImmutableMap.of("sub", subject, "iss", issuer);
    this.userInfo = userInfo;
    this.sub = subject;
    this.issuer = issuer;
    this.idToken = idToken;
    this.accessTokenValue = accessTokenValue;
    this.refreshTokenValue = refreshTokenValue;

    setAuthenticated(true);
  }


  /*
   * (non-Javadoc)
   *
   * @see org.springframework.security.core.Authentication#getCredentials()
   */
  @Override
  public Object getCredentials() {
    return accessTokenValue;
  }

  /**
   * Get the principal of this object, an immutable map of the subject and issuer.
   */
  @Override
  public Object getPrincipal() {
    return principal;
  }

  public String getSub() {
    return sub;
  }

  /**
   * @return the idTokenValue
   */
  public JWT getIdToken() {
    return idToken;
  }

  /**
   * @return the accessTokenValue
   */
  public String getAccessTokenValue() {
    return accessTokenValue;
  }

  /**
   * @return the refreshTokenValue
   */
  public String getRefreshTokenValue() {
    return refreshTokenValue;
  }

  /**
   * @return the issuer
   */
  public String getIssuer() {
    return issuer;
  }

  /**
   * @return the userInfo
   */
  public UserInfo getUserInfo() {
    return userInfo;
  }

  /*
   * Custom serialization to handle the JSON object
   */
  private void writeObject(ObjectOutputStream out) throws IOException {
    out.defaultWriteObject();
    if (idToken == null) {
      out.writeObject(null);
    } else {
      out.writeObject(idToken.serialize());
    }
  }
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException, ParseException {
    in.defaultReadObject();
    Object o = in.readObject();
    if (o != null) {
      idToken = JWTParser.parse((String)o);
    }
  }

}
