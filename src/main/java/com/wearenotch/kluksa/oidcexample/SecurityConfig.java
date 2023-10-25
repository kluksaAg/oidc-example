package com.wearenotch.kluksa.oidcexample;

import com.wearenotch.kluksa.oidcexample.backchannel.OidcClientSessionEventListener;
import com.wearenotch.kluksa.oidcexample.backchannel.OidcSessionRegistryAuthenticationStrategy;
import com.wearenotch.kluksa.oidcexample.backchannel.logout.OidcBackChannelLogoutAuthenticationProvider;
import com.wearenotch.kluksa.oidcexample.backchannel.session.InMemoryOidcSessionRegistry;
import com.wearenotch.kluksa.oidcexample.backchannel.session.OidcSessionRegistry;
import com.wearenotch.kluksa.oidcexample.backchannel.web.OidcBackChannelLogoutFilter;
import com.wearenotch.kluksa.oidcexample.backchannel.web.logout.OidcBackChannelLogoutHandler;
import com.wearenotch.kluksa.oidcexample.backchannel.web.logout.OidcLogoutAuthenticationConverter;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.GenericApplicationListenerAdapter;
import org.springframework.context.event.SmartApplicationListener;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.context.DelegatingApplicationListener;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import java.lang.reflect.Method;


@Configuration
@EnableWebSecurity
public class SecurityConfig {
  private final ClientRegistrationRepository clientRegistrationRepository;
  private final DelegatingApplicationListener delegatingApplicationListener;
  private final AuthenticationManagerBuilder authenticationManagerBuilder;

  public SecurityConfig(ClientRegistrationRepository clientRegistrationRepository,
                        DelegatingApplicationListener delegatingApplicationListener,
                        AuthenticationManagerBuilder authenticationManagerBuilder) {
    this.clientRegistrationRepository = clientRegistrationRepository;
    this.delegatingApplicationListener = delegatingApplicationListener;
    this.authenticationManagerBuilder = authenticationManagerBuilder;
  }

  @Bean
  public AuthenticationManager authenticationManager() {
    return new ProviderManager(
        new OidcBackChannelLogoutAuthenticationProvider());
  }

  @Bean
  public OidcLogoutAuthenticationConverter authenticationConverter() {
    return new OidcLogoutAuthenticationConverter(clientRegistrationRepository);
  }

  @Bean
  public ServletListenerRegistrationBean<HttpSessionEventPublisher> httpSessionEventPublisher() {
    return new ServletListenerRegistrationBean<>(new HttpSessionEventPublisher());
  }

  @Bean
  public SecurityFilterChain configure(final HttpSecurity http) throws Exception {
    this.authenticationManagerBuilder.authenticationProvider(new OidcBackChannelLogoutAuthenticationProvider());
    OidcSessionRegistry sessionRegistry = new InMemoryOidcSessionRegistry();

    http
        .oauth2Login(Customizer.withDefaults())
        .logout(Customizer.withDefaults())
        .sessionManagement(configurer -> {
              configurer.sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
              addSessionAuthenticationStrategy(configurer, new OidcSessionRegistryAuthenticationStrategy(sessionRegistry));
            }
        )
        .addFilterBefore(backChannelLogoutFilter(sessionRegistry), CsrfFilter.class)
        .csrf(cus -> cus.ignoringRequestMatchers("/logout"))
        .authorizeRequests(authorizeRequests ->
            authorizeRequests.anyRequest().authenticated());

    SmartApplicationListener smartListener = new GenericApplicationListenerAdapter(
        new OidcClientSessionEventListener(sessionRegistry));
    delegatingApplicationListener.addListener(smartListener);
    return http.build();
  }

  private OidcBackChannelLogoutFilter backChannelLogoutFilter(final OidcSessionRegistry sessionRegistry) throws Exception {
    OidcBackChannelLogoutFilter filter = new OidcBackChannelLogoutFilter(
        authenticationConverter(), authenticationManager());
    filter.setLogoutHandler(backChannelLogoutHandler(sessionRegistry));
    return filter;
  }


  private OidcBackChannelLogoutHandler backChannelLogoutHandler(final OidcSessionRegistry sessionRegistry) {
    final OidcBackChannelLogoutHandler oidcBackChannelLogoutHandler = new OidcBackChannelLogoutHandler();
    oidcBackChannelLogoutHandler.setSessionRegistry(sessionRegistry);
    oidcBackChannelLogoutHandler.setLogoutUri("/logout");
    return oidcBackChannelLogoutHandler;
  }

  private void addSessionAuthenticationStrategy(final SessionManagementConfigurer<HttpSecurity> configurer,
                                                final OidcSessionRegistryAuthenticationStrategy strategy) {
    try {
      final Method addSessionAuthenticationStrategy = configurer.getClass()
          .getDeclaredMethod("addSessionAuthenticationStrategy", SessionAuthenticationStrategy.class);
      addSessionAuthenticationStrategy.setAccessible(true);
      addSessionAuthenticationStrategy.invoke(configurer, strategy);
    } catch (Exception ex) {
      throw new RuntimeException(ex);
    }
  }
}
