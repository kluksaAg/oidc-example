package com.wearenotch.kluksa.oidcexample;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class OidcExampleApplication {

  @GetMapping
  @ResponseBody
  public String get(){
    return "Hello world!";
  }

  @GetMapping("/bye")
  @ResponseBody
  public String getBye() {
    return "Bye bye world!";
  }

  @GetMapping("/principal")
  @ResponseBody
  public OidcUser getOidcUserPrincipal(@AuthenticationPrincipal OidcUser principal) {
    return principal;
  }

  public static void main(String[] args) {
    SpringApplication.run(OidcExampleApplication.class, args);
  }

}
