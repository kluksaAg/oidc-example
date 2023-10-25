package com.wearenotch.kluksa.oidcexample.backchannel;

import com.wearenotch.kluksa.oidcexample.backchannel.session.OidcSessionInformation;
import com.wearenotch.kluksa.oidcexample.backchannel.session.OidcSessionRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.security.core.session.AbstractSessionEvent;
import org.springframework.security.core.session.SessionDestroyedEvent;
import org.springframework.security.core.session.SessionIdChangedEvent;

@Slf4j
public final class OidcClientSessionEventListener implements ApplicationListener<AbstractSessionEvent> {

  private final OidcSessionRegistry sessionRegistry;

  public OidcClientSessionEventListener(OidcSessionRegistry sessionRegistry) {
    this.sessionRegistry = sessionRegistry;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public void onApplicationEvent(AbstractSessionEvent event) {
    if (event instanceof SessionDestroyedEvent destroyed) {
      log.debug("Received SessionDestroyedEvent");
      this.sessionRegistry.removeSessionInformation(destroyed.getId());
      return;
    }
    if (event instanceof SessionIdChangedEvent changed) {
      log.debug("Received SessionIdChangedEvent");
      OidcSessionInformation information = this.sessionRegistry.removeSessionInformation(changed.getOldSessionId());
      if (information == null) {
        log.debug("Failed to register new session id since old session id was not found in registry");
        return;
      }
      this.sessionRegistry.saveSessionInformation(information.withSessionId(changed.getNewSessionId()));
    }
  }
}
