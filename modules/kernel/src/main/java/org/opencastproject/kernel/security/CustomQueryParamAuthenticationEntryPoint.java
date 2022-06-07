/**
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

package org.opencastproject.kernel.security;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CustomQueryParamAuthenticationEntryPoint extends LoginUrlAuthenticationEntryPoint {

  private String loginQueryParam;

  public CustomQueryParamAuthenticationEntryPoint(String loginFormUrl, String loginQueryParam) {
    super(loginFormUrl);
    Assert.notNull(loginFormUrl, "loginQueryParam cannot be null");
    this.loginQueryParam = loginQueryParam;
  }

  @Override
  protected String determineUrlToUseForThisRequest(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException exception) {

    String targetParamValue = UrlUtils.buildRequestUrl(request);
    String redirect = super.determineUrlToUseForThisRequest(request, response, exception);
    return UriComponentsBuilder.fromPath(redirect).queryParam(loginQueryParam, targetParamValue).build().toUriString();
  }

}
