package org.springframework.security.oauth2.server.authorization.authentication;

import java.util.Map;
import java.util.Set;
import lombok.Getter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

public class OAuth2PasswordAuthenticationToken extends
    OAuth2AuthorizationGrantAuthenticationToken {

  @Getter
  private final Set<String> scopes;

  /**
   * Sub-class constructor.
   *
   * @param authorizationGrantType the authorization grant type
   * @param clientPrincipal        the authenticated client principal
   * @param requestedScopes
   * @param additionalParameters   the additional parameters
   */
  public OAuth2PasswordAuthenticationToken(
      AuthorizationGrantType authorizationGrantType,
      Authentication clientPrincipal,
      Set<String> requestedScopes, Map<String, Object> additionalParameters) {
    super(authorizationGrantType, clientPrincipal, additionalParameters);
    this.scopes = requestedScopes;
  }

}