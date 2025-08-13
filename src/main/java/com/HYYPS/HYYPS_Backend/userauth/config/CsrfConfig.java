package com.HYYPS.HYYPS_Backend.userauth.config;

import com.HYYPS.HYYPS_Backend.userauth.utils.SecurityConstants;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;

@Configuration
public class CsrfConfig {

    @Bean
    public CsrfTokenRepository csrfTokenRepository() {
        CookieCsrfTokenRepository repository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        repository.setCookieName(SecurityConstants.CSRF_COOKIE_NAME);
        repository.setCookieHttpOnly(false); // Must be false so JavaScript can read it
//        repository.setCookieSecure(true); // Set to false for development
        repository.setCookiePath("/");
        repository.setCookieMaxAge(24 * 60 * 60); // 24 hours
        return repository;
    }
}