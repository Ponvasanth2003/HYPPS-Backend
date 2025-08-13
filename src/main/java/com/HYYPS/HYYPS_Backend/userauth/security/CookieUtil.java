package com.HYYPS.HYYPS_Backend.userauth.security;

import com.HYYPS.HYYPS_Backend.userauth.utils.SecurityConstants;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class CookieUtil {

    @Value("${app.cookie.secure:true}")
    private boolean cookieSecure;

    @Value("${app.cookie.domain:}")
    private String cookieDomain;

    @Value("${app.cookie.path:/}")
    private String cookiePath;

    private final JwtTokenProvider jwtTokenProvider;

    public void setJwtCookie(HttpServletResponse response, String token) {
        Cookie jwtCookie = new Cookie(SecurityConstants.JWT_COOKIE_NAME, token);
        jwtCookie.setHttpOnly(SecurityConstants.COOKIE_HTTP_ONLY);
        jwtCookie.setSecure(cookieSecure);
        jwtCookie.setPath(cookiePath);
        jwtCookie.setMaxAge(SecurityConstants.COOKIE_MAX_AGE);

        if (!cookieDomain.isEmpty()) {
            jwtCookie.setDomain(cookieDomain);
        }

        // Note: SameSite attribute needs to be set via response header in Spring Boot
        response.addHeader("Set-Cookie",
                String.format("%s=%s; Path=%s; Max-Age=%d; HttpOnly; %s SameSite=%s",
                        SecurityConstants.JWT_COOKIE_NAME,
                        token,
                        cookiePath,
                        SecurityConstants.COOKIE_MAX_AGE,
                        cookieSecure ? "Secure;" : "",
                        SecurityConstants.COOKIE_SAME_SITE
                )
        );

        log.debug("JWT cookie set for response");
    }

    public void clearJwtCookie(HttpServletResponse response) {
        Cookie jwtCookie = new Cookie(SecurityConstants.JWT_COOKIE_NAME, "");
        jwtCookie.setHttpOnly(SecurityConstants.COOKIE_HTTP_ONLY);
        jwtCookie.setSecure(cookieSecure);
        jwtCookie.setPath(cookiePath);
        jwtCookie.setMaxAge(0); // Delete immediately

        if (!cookieDomain.isEmpty()) {
            jwtCookie.setDomain(cookieDomain);
        }

        response.addCookie(jwtCookie);

        // Also add via header for better browser compatibility
        response.addHeader("Set-Cookie",
                String.format("%s=; Path=%s; Max-Age=0; HttpOnly; %s SameSite=%s",
                        SecurityConstants.JWT_COOKIE_NAME,
                        cookiePath,
                        cookieSecure ? "Secure;" : "",
                        SecurityConstants.COOKIE_SAME_SITE
                )
        );

        log.debug("JWT cookie cleared");
    }

    public String getJwtFromCookie(HttpServletRequest request) {
        if (request.getCookies() == null) {
            return null;
        }

        for (Cookie cookie : request.getCookies()) {
            if (SecurityConstants.JWT_COOKIE_NAME.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    public boolean hasValidJwtCookie(HttpServletRequest request) {
        String token = getJwtFromCookie(request);
        return token != null && jwtTokenProvider.validateToken(token);
    }
}