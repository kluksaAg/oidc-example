package com.wearenotch.kluksa.oidcexample.backchannel;

import com.wearenotch.kluksa.oidcexample.backchannel.session.OidcSessionInformation;
import com.wearenotch.kluksa.oidcexample.backchannel.session.OidcSessionRegistry;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfToken;

import java.util.Collections;
import java.util.Map;

@Slf4j
public final class OidcSessionRegistryAuthenticationStrategy implements SessionAuthenticationStrategy {

  private final OidcSessionRegistry sessionRegistry;

  public OidcSessionRegistryAuthenticationStrategy(OidcSessionRegistry sessionRegistry) {
    this.sessionRegistry = sessionRegistry;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public void onAuthentication(Authentication authentication, HttpServletRequest request, HttpServletResponse response)
      throws SessionAuthenticationException {
    HttpSession session = request.getSession(false);
    if (session == null) {
      return;
    }
    if (!(authentication.getPrincipal() instanceof OidcUser user)) {
      return;
    }
    String sessionId = session.getId();
    CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
    Map<String, String> headers = (csrfToken != null)
        ? Map.of(csrfToken.getHeaderName(), csrfToken.getToken()) : Collections.emptyMap();
    OidcSessionInformation registration = new OidcSessionInformation(sessionId, headers, user);
    if (log.isTraceEnabled()) {
      log.trace(String.format("Linking a provider [%s] session to this client's session", user.getIssuer()));
    }
    this.sessionRegistry.saveSessionInformation(registration);
  }
}
