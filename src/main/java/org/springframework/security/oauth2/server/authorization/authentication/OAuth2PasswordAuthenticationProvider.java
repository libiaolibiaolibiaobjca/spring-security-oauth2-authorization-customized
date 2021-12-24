package org.springframework.security.oauth2.server.authorization.authentication;

import java.security.Principal;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.function.Supplier;
import lombok.Setter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JoseHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

/**
 * An AuthenticationProvider implementation for the OAuth 2.0 Password Grant. <br/> The Security BCP
 * effectively deprecates the Implicit flow as well as the Password grant out of OAuth entirely, and
 * further recommends using PKCE even for web server apps @link https://oauth.net/2/oauth-best-practice/
 *
 * @author label
 * @date 2021-12-17
 * @see OAuth2ClientCredentialsAuthenticationProvider
 */
public class OAuth2PasswordAuthenticationProvider implements AuthenticationProvider {

  private final OAuth2AuthorizationService authorizationService;
  private final JwtEncoder jwtEncoder;
  @Setter
  private OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer = (context) -> {
  };
  @Setter
  private ProviderSettings providerSettings;

  private static final StringKeyGenerator DEFAULT_REFRESH_TOKEN_GENERATOR =
      new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);
  private Supplier<String> refreshTokenGenerator = DEFAULT_REFRESH_TOKEN_GENERATOR::generateKey;

  public OAuth2PasswordAuthenticationProvider(OAuth2AuthorizationService authorizationService,
      JwtEncoder jwtEncoder) {
    Assert.notNull(authorizationService, "authorizationService cannot be null");
    Assert.notNull(jwtEncoder, "jwtEncoder cannot be null");
    this.authorizationService = authorizationService;
    this.jwtEncoder = jwtEncoder;
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return org.springframework.security.oauth2.server.authorization.authentication.OAuth2PasswordAuthenticationToken.class.isAssignableFrom(authentication);
  }

  @Override
  public Authentication authenticate(Authentication authentication)
      throws AuthenticationException {
    org.springframework.security.oauth2.server.authorization.authentication.OAuth2PasswordAuthenticationToken passwordAuthenticationToken = (org.springframework.security.oauth2.server.authorization.authentication.OAuth2PasswordAuthenticationToken) authentication;
    OAuth2ClientAuthenticationToken clientPrincipal = OAuth2AuthenticationProviderUtils.getAuthenticatedClientElseThrowInvalidClient(
        authentication);

    if (clientPrincipal == null || !clientPrincipal.isAuthenticated()) {
      throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
    }

    RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
    if (!registeredClient.getAuthorizationGrantTypes()
        .contains(AuthorizationGrantType.PASSWORD)) {
      throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
    }

    Set<String> authorizedScopes = registeredClient.getScopes();    // Default to configured scopes
    if (!CollectionUtils.isEmpty(passwordAuthenticationToken.getScopes())) {
      for (String requestedScope : passwordAuthenticationToken.getScopes()) {
        if (!registeredClient.getScopes().contains(requestedScope)) {
          throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
        }
      }
      authorizedScopes = new LinkedHashSet<>(passwordAuthenticationToken.getScopes());
    }
    String issuer = this.providerSettings != null ? this.providerSettings.getIssuer() : null;

    JoseHeader.Builder headersBuilder = JwtUtils.headers();
    JwtClaimsSet.Builder claimsBuilder = JwtUtils.accessTokenClaims(
        registeredClient, issuer, clientPrincipal.getName(), authorizedScopes);

    // @formatter:off
    JwtEncodingContext context = JwtEncodingContext.with(headersBuilder, claimsBuilder)
        .registeredClient(registeredClient)
        .principal(clientPrincipal)
        .authorizedScopes(authorizedScopes)
        .tokenType(OAuth2TokenType.ACCESS_TOKEN)
        .authorizationGrantType(AuthorizationGrantType.PASSWORD)
        .authorizationGrant(passwordAuthenticationToken)
        .build();
    // @formatter:on

    this.jwtCustomizer.customize(context);

    JoseHeader headers = context.getHeaders().build();
    JwtClaimsSet claims = context.getClaims().build();
    Jwt jwtAccessToken = this.jwtEncoder.encode(headers, claims);

    OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
        jwtAccessToken.getTokenValue(), jwtAccessToken.getIssuedAt(),
        jwtAccessToken.getExpiresAt(), authorizedScopes);

    // --
    Jwt jwtIdToken = null;
    if (authorizedScopes.contains(OidcScopes.OPENID)) {
      headersBuilder = JwtUtils.headers();

      claimsBuilder = JwtUtils.idTokenClaims(
          registeredClient, issuer, passwordAuthenticationToken.getName(), null);

      // @formatter:off
      context = JwtEncodingContext.with(headersBuilder, claimsBuilder)
          .registeredClient(registeredClient)
          .principal(clientPrincipal)
          .authorization(null)
          .authorizedScopes(authorizedScopes)
          .tokenType(new OAuth2TokenType(OidcParameterNames.ID_TOKEN))
          .authorizationGrantType(AuthorizationGrantType.PASSWORD)
          .authorizationGrant(passwordAuthenticationToken)
          .build();
      // @formatter:on

      this.jwtCustomizer.customize(context);

      headers = context.getHeaders().build();
      claims = context.getClaims().build();
      jwtIdToken = this.jwtEncoder.encode(headers, claims);
    }

    OidcIdToken idToken;
    if (jwtIdToken != null) {
      idToken = new OidcIdToken(jwtIdToken.getTokenValue(), jwtIdToken.getIssuedAt(),
          jwtIdToken.getExpiresAt(), jwtIdToken.getClaims());
    } else {
      idToken = null;
    }

    // @formatter:off
    OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(
            registeredClient)
        .principalName(clientPrincipal.getName())
        .authorizationGrantType(AuthorizationGrantType.PASSWORD)
        .token(accessToken,
            (metadata) ->
                metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                    jwtAccessToken.getClaims()))

        .attribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME, authorizedScopes)
        .attribute(Principal.class.getName(), passwordAuthenticationToken)
        ;

    // 填充 refresh_token
    OAuth2RefreshToken refreshToken = null;

    TokenSettings tokenSettings = registeredClient.getTokenSettings();
    if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)
        && !tokenSettings.isReuseRefreshTokens()) {
      refreshToken = generateRefreshToken(tokenSettings.getRefreshTokenTimeToLive());
      authorizationBuilder.refreshToken(refreshToken);
    }

    if (idToken != null) {
      authorizationBuilder
          .token(idToken,
              (metadata) ->
                  metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                      idToken.getClaims()));
    }
    this.authorizationService.save(authorizationBuilder.build());

    return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken,
        refreshToken);
  }

  private OAuth2RefreshToken generateRefreshToken(Duration tokenTimeToLive) {
    Instant issuedAt = Instant.now();
    Instant expiresAt = issuedAt.plus(tokenTimeToLive);
    return new OAuth2RefreshToken(this.refreshTokenGenerator.get(), issuedAt, expiresAt);
  }

}