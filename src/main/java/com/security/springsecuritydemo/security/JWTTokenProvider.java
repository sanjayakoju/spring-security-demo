package com.security.springsecuritydemo.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.springsecuritydemo.model.User;
import io.jsonwebtoken.*;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Slf4j
@Component
public class JWTTokenProvider {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.token.expire-seconds}")
    private long tokenExpireInSeconds;

    @PostConstruct
    protected void init() {
        jwtSecret = Base64.getEncoder().encodeToString(jwtSecret.getBytes());
    }

    //generate token for user
    public Map<String, String> generateToken(Authentication authentication) throws JsonProcessingException {
        UserDetail userDetail = (UserDetail) authentication.getPrincipal();
        User user = userDetail.getUser();
        Claims claims = Jwts.claims().setSubject(user.getUsername());

        claims.put("userId", user.getId());
        claims.put("username", user.getUsername());
        System.out.println("Username + " + user.getUsername());
        System.out.println("Authorities + " + user.getRoles());
        ObjectMapper objectMapper = new ObjectMapper();
        claims.put("roles", objectMapper.writeValueAsString(user.getRoles()));

        return doGenerateToken(claims);
    }

    //while creating the token -
    //1. Define  claims of the token, like Issuer, Expiration, Subject, and the ID
    //2. Sign the JWT using the HS512 algorithm and secret key.
    //3. According to JWS Compact Serialization(https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-3.1)
    //   compaction of the JWT to a URL-safe string
    private Map<String, String> doGenerateToken(Claims claims) {
        try {
            long refreshTokenExpirationInMillis = 1 * 24 * 60 * 60 * 1000; // 1 day

            final String accessToken = Jwts.builder()
                    .setClaims(claims)
                    .setIssuedAt(new Date())
                    .setExpiration(new Date(System.currentTimeMillis() + (tokenExpireInSeconds)))
                    .signWith(SignatureAlgorithm.HS256, jwtSecret)
                    .compact();

            final String refreshToken = Jwts.builder()
                    .setClaims(claims)
                    .setIssuedAt(new Date())
                    .setExpiration(new Date(System.currentTimeMillis() + (refreshTokenExpirationInMillis)))
                    .signWith(SignatureAlgorithm.HS256, jwtSecret)
                    .compact();
            Map<String, String> map = new HashMap<>();
            map.put("accessToken", accessToken);
            map.put("expiredIn", String.valueOf(new Date(System.currentTimeMillis() + (tokenExpireInSeconds))));
            map.put("refreshToken", refreshToken);
            log.info("JWT Token Created Successfully !!!");
            return map;
        } catch (MalformedJwtException | UnsupportedJwtException | IllegalArgumentException ex) {
            log.error("Invalid : JWT Token Builder !!!");
        }
        return null;
    }

    //validate token
    public boolean validateToken(String token, UserDetails userDetails) {
        final String userName = getUsernameFromToken(token);
        try {
            if ((userName.equals(userDetails.getUsername())) && !isTokenExpired(token)) {
                return true;
            }
        } catch (ExpiredJwtException ex) {
            log.error("Expired : JWT Token !!!");
        } catch (MalformedJwtException | UnsupportedJwtException | IllegalArgumentException ex) {
            log.error("Invalid: JWT Token !!!");
            ex.printStackTrace();
        }
        return false;
    }

    private boolean isTokenExpired(String token) {
        try {
            final Date expiration = getExpirationFromToken(token);
            return expiration.before(new Date());
        } catch (ExpiredJwtException ex) {
            log.error("Expired : JWT Token !!!");
        }
        return false;
    }

    //retrieve expiration date from jwt token
    private Date getExpirationFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    //retrieve username from jwt token
    public String getUsernameFromToken(String token) {
        try {
            return getClaimFromToken(token, Claims::getSubject);
        } catch (UsernameNotFoundException ex) {
            log.error("User Not Found !!!");
        }
        return null;
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        try {
            final Claims claims = getAllClaimsFromToken(token);
            return claimsResolver.apply(claims);
        } catch (NullPointerException ex) {
            log.error("Claims Not Found !!!");
            ex.printStackTrace();
        }
        return null;
    }

    //for retrieving any information from token we will need the secret key
    private Claims getAllClaimsFromToken(String token) {
        Claims claims = null;
        try {
            claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
        } catch (ExpiredJwtException ex) {
            log.error("Expired : JWT Token !!!");
        } catch (MalformedJwtException | UnsupportedJwtException | IllegalArgumentException ex) {
            log.error("Invalid: JWT Token");
            ex.printStackTrace();
        }
        return claims;
    }
}
