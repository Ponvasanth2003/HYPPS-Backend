package com.HYYPS.HYYPS_Backend.userauth.config;

import com.HYYPS.HYYPS_Backend.userauth.security.JwtAuthenticationFilter;
import com.HYYPS.HYYPS_Backend.userauth.security.CustomUserDetailsService;
import com.HYYPS.HYYPS_Backend.userauth.service.RateLimitService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Autowired
    private RateLimitService rateLimitService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
        requestHandler.setCsrfRequestAttributeName("_csrf");

        http
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/signup", "/api/auth/verify-otp", "/api/auth/login",
                                "/api/auth/resend-otp", "/api/auth/forgot-password",
                                "/api/auth/reset-password", "/api/auth/social-login").permitAll()
                        .requestMatchers("/api/auth/logout", "/api/auth/refresh-token").authenticated()
                        .requestMatchers("/api/health", "/actuator/**").permitAll()
                        .requestMatchers("/api/auth/roles").permitAll()

                        // NEW: Teacher verification endpoints
                        .requestMatchers("/api/teacher/verification/**").hasRole("TEACHER")
                        .requestMatchers("/api/kyc/**").hasRole("TEACHER")

                        // NEW: Admin verification endpoints
                        .requestMatchers("/api/admin/verifications/**").hasRole("ADMIN")
                        .requestMatchers("/api/admin/kyc/**").hasRole("ADMIN")

                        .requestMatchers(
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/v3/api-docs/**",
                                "/api-docs/**",
                                "/swagger-resources/**",
                                "/webjars/**",
                                "/"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/api/**")  // 🔥 Disable CSRF for all API routes
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}