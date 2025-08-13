package com.HYYPS.HYYPS_Backend.userauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.CommonsRequestLoggingFilter;

@Configuration
public class RateLimitConfig {

    @Bean
    public CommonsRequestLoggingFilter requestLoggingFilter() {
        CommonsRequestLoggingFilter loggingFilter = new CommonsRequestLoggingFilter();
        loggingFilter.setIncludeClientInfo(true);
        loggingFilter.setIncludeQueryString(true);
        loggingFilter.setIncludePayload(false); // Don't log sensitive payload data
        loggingFilter.setIncludeHeaders(false); // Don't log sensitive headers
        loggingFilter.setMaxPayloadLength(1000);
        return loggingFilter;
    }
}