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

import javax.servlet.http.HttpServletRequest;

public class StaticSingleIssuerService {

  private String issuer;

  /**
   * @return the issuer
   */
  public String getIssuer() {
    return issuer;
  }

  /**
   * @param issuer the issuer to set
   */
  public void setIssuer(String issuer) {
    if (Strings.isNullOrEmpty(issuer)) {
      throw new IllegalArgumentException("Issuer must not be null or empty.");
    }
    this.issuer = issuer;
  }

  /**
   * Always returns the configured issuer URL
   *
   * @see org.mitre.openid.connect.client.service.IssuerService#getIssuer(javax.servlet.http.HttpServletRequest)
   */
  public IssuerServiceResponse getIssuer(HttpServletRequest request) {
    return new IssuerServiceResponse(getIssuer(), null, null);
  }

}
