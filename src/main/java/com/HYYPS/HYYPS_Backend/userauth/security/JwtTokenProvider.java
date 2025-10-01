package com.HYYPS.HYYPS_Backend.userauth.security;

import com.HYYPS.HYYPS_Backend.userauth.entity.Role;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Set;
import java.util.Collections;
import java.util.stream.Collectors;

@Component
@Slf4j
public class JwtTokenProvider {

    @Value("${app.jwt.secret:mySecretKey}")
    private String jwtSecret;

    @Value("${app.jwt.expiration:86400000}") // 24 hours
    private long jwtExpirationInMs;

    @Value("${app.jwt.refresh-expiration:604800000}") // 7 days
    private long refreshTokenExpirationInMs;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }

    /**
     * NEW METHOD: Generate token with role names from database (String set)
     * This is the PREFERRED method - uses database role names directly
     *
     * @param authentication Spring Security authentication object
     * @param roleNames Set of role names from database (e.g., "STUDENT", "TEACHER", "ADMIN")
     * @return JWT token string with roles embedded
     */
    public String generateTokenWithRoleNames(Authentication authentication, Set<String> roleNames) {
        String email = authentication.getName();
        Date expiryDate = new Date(System.currentTimeMillis() + jwtExpirationInMs);

        // Join role names with comma separator, or empty string if no roles
        String rolesClaim = roleNames != null && !roleNames.isEmpty()
                ? String.join(",", roleNames)
                : "";

        log.debug("Generating token for {} with roles: {}", email, rolesClaim);

        return Jwts.builder()
                .setSubject(email)
                .claim("roles", rolesClaim)
                .claim("type", "access")
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(getSigningKey())
                .compact();
    }

    /**
     * DEPRECATED: Keep for backward compatibility with old enum-based system
     * DO NOT USE - Use generateTokenWithRoleNames() instead
     *
     * @deprecated This method uses the old enum-based Role system which is no longer populated.
     *             Use {@link #generateTokenWithRoleNames(Authentication, Set)} instead.
     */
    @Deprecated
    public String generateToken(Authentication authentication, Set<Role> roles) {
        String email = authentication.getName();
        Date expiryDate = new Date(System.currentTimeMillis() + jwtExpirationInMs);

        String rolesClaim = roles != null && !roles.isEmpty()
                ? roles.stream().map(Role::name).collect(Collectors.joining(","))
                : "";

        log.warn("Using deprecated generateToken method with enum roles for {} - consider migrating to generateTokenWithRoleNames", email);

        return Jwts.builder()
                .setSubject(email)
                .claim("roles", rolesClaim)
                .claim("type", "access")
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(getSigningKey())
                .compact();
    }

    /**
     * Generate refresh token (no roles needed)
     *
     * @param email User email
     * @return JWT refresh token
     */
    public String generateRefreshToken(String email) {
        Date expiryDate = new Date(System.currentTimeMillis() + refreshTokenExpirationInMs);

        return Jwts.builder()
                .setSubject(email)
                .claim("type", "refresh")
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(getSigningKey())
                .compact();
    }

    /**
     * Extract email from JWT token
     *
     * @param token JWT token string
     * @return User email
     */
    public String getEmailFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }

    /**
     * NEW METHOD: Get role names as strings from token
     * This returns the database role names (STUDENT, TEACHER, ADMIN)
     * This is the PREFERRED method for extracting roles
     *
     * @param token JWT token string
     * @return Set of role names from database
     */
    public Set<String> getRoleNamesFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

        String rolesClaim = claims.get("roles", String.class);

        // Handle empty or null roles
        if (rolesClaim == null || rolesClaim.trim().isEmpty()) {
            log.debug("No roles found in token");
            return Collections.emptySet();
        }

        // Split by comma and filter out empty strings
        Set<String> roleNames = Set.of(rolesClaim.split(","))
                .stream()
                .map(String::trim)
                .filter(role -> !role.isEmpty())
                .collect(Collectors.toSet());

        log.debug("Extracted roles from token: {}", roleNames);
        return roleNames;
    }

    /**
     * DEPRECATED: Keep for backward compatibility
     * DO NOT USE - Use getRoleNamesFromToken() instead
     *
     * @deprecated This method tries to convert role names to Role enum which may fail.
     *             Use {@link #getRoleNamesFromToken(String)} instead.
     */
    @Deprecated
    public Set<Role> getRolesFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

        String rolesClaim = claims.get("roles", String.class);
        if (rolesClaim == null || rolesClaim.isEmpty()) {
            return Collections.emptySet();
        }

        try {
            return Set.of(rolesClaim.split(","))
                    .stream()
                    .map(String::trim)
                    .filter(role -> !role.isEmpty())
                    .map(Role::valueOf)
                    .collect(Collectors.toSet());
        } catch (IllegalArgumentException e) {
            log.error("Failed to parse roles from token: {}", rolesClaim, e);
            return Collections.emptySet();
        }
    }

    /**
     * Check if token is a refresh token
     *
     * @param token JWT token string
     * @return true if refresh token, false otherwise
     */
    public boolean isRefreshToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            return "refresh".equals(claims.get("type", String.class));
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Get token expiration date
     *
     * @param token JWT token string
     * @return Expiration date
     */
    public Date getExpirationDateFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getExpiration();
    }

    /**
     * Validate JWT token
     * Checks signature, expiration, format, etc.
     *
     * @param authToken JWT token string
     * @return true if valid, false otherwise
     */
    public boolean validateToken(String authToken) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(authToken);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException ex) {
            log.error("Invalid JWT signature");
        } catch (MalformedJwtException ex) {
            log.error("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            log.error("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            log.error("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            log.error("JWT claims string is empty");
        }
        return false;
    }

    /**
     * Get configured JWT expiration time in milliseconds
     *
     * @return Expiration time in ms
     */
    public long getJwtExpirationInMs() {
        return jwtExpirationInMs;
    }

    /**
     * Get configured refresh token expiration time in milliseconds
     *
     * @return Refresh expiration time in ms
     */
    public long getRefreshTokenExpirationInMs() {
        return refreshTokenExpirationInMs;
    }

    /**
     * Check if token is expired (for manual validation)
     *
     * @param token JWT token string
     * @return true if expired, false otherwise
     */
    public boolean isTokenExpired(String token) {
        try {
            Date expiration = getExpirationDateFromToken(token);
            return expiration.before(new Date());
        } catch (Exception e) {
            return true;
        }
    }

    /**
     * Get remaining time until token expiration in milliseconds
     *
     * @param token JWT token string
     * @return Remaining time in ms, or 0 if expired/invalid
     */
    public long getRemainingExpirationTime(String token) {
        try {
            Date expiration = getExpirationDateFromToken(token);
            long remainingTime = expiration.getTime() - System.currentTimeMillis();
            return Math.max(0, remainingTime);
        } catch (Exception e) {
            return 0;
        }
    }
}