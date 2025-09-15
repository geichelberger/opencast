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
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.net.URI;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class OIDCAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

  protected static final String REDIRECT_URI_SESION_VARIABLE = "redirect_uri";
  protected static final String CODE_VERIFIER_SESSION_VARIABLE = "code_verifier";
  protected static final String STATE_SESSION_VARIABLE = "state";
  protected static final String NONCE_SESSION_VARIABLE = "nonce";
  protected static final String ISSUER_SESSION_VARIABLE = "issuer";
  protected static final String TARGET_SESSION_VARIABLE = "target";
  protected static final int HTTP_SOCKET_TIMEOUT = 30000;
  public static final String FILTER_PROCESSES_URL = "/openid_connect_login";

  private TargetLinkURIAuthenticationSuccessHandler targetSuccessHandler
      = new TargetLinkURIAuthenticationSuccessHandler();
  private TargetLinkURIChecker deepLinkFilter;

  private DynamicServerConfigurationService servers = new DynamicServerConfigurationService();

  private StaticSingleIssuerService issuerService = new StaticSingleIssuerService();

  public OIDCAuthenticationFilter() {
    super(FILTER_PROCESSES_URL);
    targetSuccessHandler.passthrough = super.getSuccessHandler();
    super.setAuthenticationSuccessHandler(targetSuccessHandler);
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

    if (!Strings.isNullOrEmpty(request.getParameter("error"))) {

      // there's an error coming back from the server, need to handle this
      handleError(request, response);
      return null; // no auth, response is sent to display page or something

    } else if (!Strings.isNullOrEmpty(request.getParameter("code"))) {

      // we got back the code, need to process this to get our tokens
      Authentication auth = handleAuthorizationCodeResponse(request, response);
      return auth;

    } else {

      // not an error, not a code, must be an initial login of some type
      handleAuthorizationRequest(request, response);

      return null; // no auth, response redirected to the server's Auth Endpoint (or possibly to the account chooser)
    }
  }

  protected void handleError(HttpServletRequest request, HttpServletResponse response) throws IOException {

    String error = request.getParameter("error");
    String errorDescription = request.getParameter("error_description");
    String errorURI = request.getParameter("error_uri");

    throw new OidcAuthenticationServiceException(error, errorDescription, errorURI);
  }

  protected Authentication handleAuthorizationCodeResponse(HttpServletRequest request, HttpServletResponse response) {

    String authorizationCode = request.getParameter("code");

    HttpSession session = request.getSession();

    // check for state, if it doesn't match we bail early
    String storedState = getStoredState(session);

    // look up the issuer that we set out to talk to
    String issuer = getStoredSessionString(session, ISSUER_SESSION_VARIABLE);

    // pull the configurations based on that issuer
    OIDCProviderMetadata serverConfig = servers.getServerConfiguration(new Issuer(issuer));

    try {
      AuthenticationResponse authenticationResponse = AuthenticationResponseParser.parse(
          URI.create(request.getRequestURI()));

      State requestState = authenticationResponse.getState();

      if (storedState == null || !storedState.equals(requestState.toString())) {
        throw new AuthenticationServiceException(
            "State parameter mismatch on return. Expected " + storedState + " got " + requestState);
      }

      if (authenticationResponse instanceof AuthenticationErrorResponse) {
        throw new AuthenticationServiceException(
            authenticationResponse.toErrorResponse()
                .getErrorObject()
                .getDescription()
        );
      }

      AuthorizationCode code = authenticationResponse.toSuccessResponse().getAuthorizationCode();

      var success = authenticationResponse.toSuccessResponse();

      JWT idToken = success.getIDToken();
      JWTClaimsSet idClaims = idToken.getJWTClaimsSet();

      new IDTokenValidator(success.getIssuer(), new, serverConfig.getIDTokenJWSAlgs());

    } catch (ParseException | java.text.ParseException e) {
      throw new RuntimeException(e);
    }

    new PendingOIDCAuthenticationToken(au)

    PendingOIDCAuthenticationToken token = new PendingOIDCAuthenticationToken(authorizationCode,
        authenticationRequest.getState().toString(),
        authenticationRequest.getNonce().toString(),
        serverConfig,
        issuer);
  }

  /**
   * Initiate an Authorization request
   *
   * @param request
   *            The request from which to extract parameters and perform the
   *            authentication
   * @param response
   * @throws IOException
   *             If an input or output exception occurs
   */
  protected void handleAuthorizationRequest(HttpServletRequest request,
      HttpServletResponse response) throws IOException {

    HttpSession session = request.getSession();

    IssuerServiceResponse issResp = issuerService.getIssuer(request);

    if (issResp == null) {
      logger.error("Null issuer response returned from service.");
      throw new AuthenticationServiceException("No issuer found.");
    }

    if (issResp.shouldRedirect()) {
      response.sendRedirect(issResp.getRedirectUrl());
    } else {
      String issuer = issResp.getIssuer();

      if (!Strings.isNullOrEmpty(issResp.getTargetLinkUri())) {
        // there's a target URL in the response, we should save this so we can forward to it later
        session.setAttribute(TARGET_SESSION_VARIABLE, issResp.getTargetLinkUri());
      }

      if (Strings.isNullOrEmpty(issuer)) {
        logger.error("No issuer found: " + issuer);
        throw new AuthenticationServiceException("No issuer found: " + issuer);
      }

      OIDCProviderMetadata serverConfig = servers.getServerConfiguration(new Issuer(issuer));
      if (serverConfig == null) {
        logger.error("No server configuration found for issuer: " + issuer);
        throw new AuthenticationServiceException("No server configuration found for issuer: " + issuer);
      }

      State state = new State();
      Nonce nonce = new Nonce();

      ClientID clientID = new ClientID("123");
      URI callback = URI.create("https://localhost:8080/openid_connect_login");
      AuthenticationRequest authenticationRequest = new AuthenticationRequest.Builder(
          new ResponseType("code"),
          new Scope("openid"),
          clientID,
          callback)
          .endpointURI(serverConfig.getAuthorizationEndpointURI())
          .state(state)
          .nonce(nonce)
          .build();

      response.sendRedirect(authenticationRequest.toURI().toString());
    }
  }

  protected static String getStoredState(HttpSession session) {
    return getStoredSessionString(session, STATE_SESSION_VARIABLE);
  }


  private static String getStoredSessionString(HttpSession session, String key) {
    Object o = session.getAttribute(key);
    if (o instanceof String) {
      return o.toString();
    } else {
      return null;
    }
  }

  protected class TargetLinkURIAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private AuthenticationSuccessHandler passthrough;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
        HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {

      HttpSession session = request.getSession();

      // check to see if we've got a target
      String target = getStoredSessionString(session, TARGET_SESSION_VARIABLE);

      if (!Strings.isNullOrEmpty(target)) {
        session.removeAttribute(TARGET_SESSION_VARIABLE);

        if (deepLinkFilter != null) {
          target = deepLinkFilter.filter(target);
        }

        response.sendRedirect(target);
      } else {
        // if the target was blank, use the default behavior here
        passthrough.onAuthenticationSuccess(request, response, authentication);
      }

    }

  }

}
