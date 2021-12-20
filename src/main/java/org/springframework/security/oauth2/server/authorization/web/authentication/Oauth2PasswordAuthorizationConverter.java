package org.springframework.security.oauth2.server.authorization.web.authentication;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2PasswordAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

/**
 * Attempts to extract an Access Token Request from HttpServletRequest for the OAuth 2.0 Client
 * Credentials Grant and then converts it to an OAuth2PasswordAuthenticationToken used for
 * authenticating the authorization grant. See Also: AuthenticationConverter,
 * OAuth2PasswordAuthenticationToken, OAuth2TokenEndpointFilter
 *
 * @author label
 * @date 2021-12-17
 */
public class Oauth2PasswordAuthorizationConverter implements AuthenticationConverter {

  @Override
  public Authentication convert(HttpServletRequest request) {
    // grant_type (REQUIRED)
    String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
    if (!AuthorizationGrantType.PASSWORD.getValue().equals(grantType)) {
      return null;
    }

    MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);
    // scope (OPTIONAL)
    String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);

    validUnq(parameters, OAuth2ParameterNames.SCOPE);
    validUnq(parameters, OAuth2ParameterNames.USERNAME);
    validUnq(parameters, OAuth2ParameterNames.PASSWORD);

    Set<String> requestedScopes = null;
    if (StringUtils.hasText(scope)) {
      requestedScopes = new HashSet<>(
          Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
    }

    Map<String, Object> additionalParameters = new HashMap();
    parameters.forEach((key, value) -> {
      if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
          !key.equals(OAuth2ParameterNames.SCOPE) &&
          !key.equals(OAuth2ParameterNames.PASSWORD)
      ) {
        additionalParameters.put(key, value.get(0));
      }
    });

    return new OAuth2PasswordAuthenticationToken(
        AuthorizationGrantType.PASSWORD,
        SecurityContextHolder.getContext().getAuthentication(),
        requestedScopes, additionalParameters);
  }

  private void validUnq(MultiValueMap<String, String> parameters, String p) {
    String v = parameters.getFirst(p);
    if (StringUtils.hasText(v) &&
        parameters.get(p).size() != 1) {
      OAuth2EndpointUtils.throwError(
          OAuth2ErrorCodes.INVALID_REQUEST,
          p,
          OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
    }
  }
}