package com.security.springsecuritydemo.model;

import lombok.Data;

@Data
public class AuthResponse {
    private String accessToken;
    private String expiredIn;
    private String refreshToken;
}
