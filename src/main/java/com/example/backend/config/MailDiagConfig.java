// src/main/java/com.example.backend/config/MailDiagConfig.java
package com.example.backend.config;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class MailDiagConfig {
  private final Environment env;

  @PostConstruct
  void diag() {
    String user = env.getProperty("spring.mail.username");
    String pass = env.getProperty("spring.mail.password");
    log.info("[MAIL-DIAG] username={}, pass_set={}, pass_len={}",
        user, pass != null, pass == null ? 0 : pass.length());
  }
}
