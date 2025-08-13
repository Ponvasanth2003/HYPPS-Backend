package com.HYYPS.HYYPS_Backend.userauth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SocialUserInfo {
    private String email;
    private String name;
    private String profilePicture;
    private String provider;
}