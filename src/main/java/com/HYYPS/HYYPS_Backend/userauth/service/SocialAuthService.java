package com.HYYPS.HYYPS_Backend.userauth.service;

import com.HYYPS.HYYPS_Backend.userauth.dto.SocialLoginRequestDto;
import com.HYYPS.HYYPS_Backend.userauth.dto.SocialUserInfo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;

import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class SocialAuthService {

    private final RestTemplate restTemplate = new RestTemplate();

    public SocialUserInfo verifyAndGetUserInfo(SocialLoginRequestDto request) {
        switch (request.getProvider().toUpperCase()) {
            case "GOOGLE":
                return verifyGoogleToken(request);
            case "FACEBOOK":
                return verifyFacebookToken(request);
            default:
                throw new RuntimeException("Unsupported social provider: " + request.getProvider());
        }
    }

    private SocialUserInfo verifyGoogleToken(SocialLoginRequestDto request) {
        try {
            // For Google ID tokens, use tokeninfo endpoint
            String url = "https://oauth2.googleapis.com/tokeninfo?id_token=" + request.getToken();
            log.info("Verifying Google token. Token length: {}, Token prefix: {}",
                    request.getToken().length(),
                    request.getToken().substring(0, Math.min(20, request.getToken().length())));

            ResponseEntity<Map> response = restTemplate.getForEntity(url, Map.class);
            Map<String, Object> tokenInfo = response.getBody();

            if (tokenInfo == null) {
                log.error("No response body from Google tokeninfo");
                throw new RuntimeException("No response from Google token verification");
            }

            if (tokenInfo.containsKey("error")) {
                log.error("Google token verification error: {}", tokenInfo.get("error"));
                throw new RuntimeException("Invalid Google token: " + tokenInfo.get("error"));
            }

            // Extract user information directly from the tokeninfo response
            SocialUserInfo socialUserInfo = new SocialUserInfo();
            socialUserInfo.setEmail((String) tokenInfo.get("email"));
            socialUserInfo.setName((String) tokenInfo.get("name"));
            socialUserInfo.setProfilePicture((String) tokenInfo.get("picture"));
            socialUserInfo.setProvider("GOOGLE");

            // Validate required fields
            if (socialUserInfo.getEmail() == null || socialUserInfo.getEmail().isEmpty()) {
                throw new RuntimeException("No email found in Google token");
            }

            log.info("Google token verified successfully for email: {}", socialUserInfo.getEmail());
            return socialUserInfo;

        } catch (Exception e) {
            log.error("Google token verification failed: {}", e.getMessage(), e);
            throw new RuntimeException("Google authentication failed: " + e.getMessage());
        }
    }

    private SocialUserInfo verifyFacebookToken(SocialLoginRequestDto request) {
        try {
            // For Facebook, the token is an access token
            String url = "https://graph.facebook.com/me?fields=id,name,email,picture&access_token=" + request.getToken();
            log.info("Verifying Facebook token");

            ResponseEntity<Map> response = restTemplate.getForEntity(url, Map.class);
            Map<String, Object> userData = response.getBody();

            if (userData == null) {
                log.error("No response body from Facebook API");
                throw new RuntimeException("No response from Facebook API");
            }

            if (userData.containsKey("error")) {
                log.error("Facebook token verification error: {}", userData.get("error"));
                throw new RuntimeException("Invalid Facebook token: " + userData.get("error"));
            }

            SocialUserInfo socialUserInfo = new SocialUserInfo();
            socialUserInfo.setEmail((String) userData.get("email"));
            socialUserInfo.setName((String) userData.get("name"));

            // Extract profile picture URL
            Map<String, Object> picture = (Map<String, Object>) userData.get("picture");
            if (picture != null) {
                Map<String, Object> data = (Map<String, Object>) picture.get("data");
                if (data != null) {
                    socialUserInfo.setProfilePicture((String) data.get("url"));
                }
            }

            socialUserInfo.setProvider("FACEBOOK");

            // Validate required fields
            if (socialUserInfo.getEmail() == null || socialUserInfo.getEmail().isEmpty()) {
                throw new RuntimeException("No email found in Facebook response");
            }

            log.info("Facebook token verified successfully for email: {}", socialUserInfo.getEmail());
            return socialUserInfo;

        } catch (Exception e) {
            log.error("Facebook token verification failed: {}", e.getMessage(), e);
            throw new RuntimeException("Facebook authentication failed: " + e.getMessage());
        }
    }
}