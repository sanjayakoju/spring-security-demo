package com.security.springsecuritydemo.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.security.springsecuritydemo.model.AuthResponse;
import com.security.springsecuritydemo.model.User;
import com.security.springsecuritydemo.security.JWTTokenProvider;
import com.security.springsecuritydemo.security.UserServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    @Autowired
    private JWTTokenProvider jwtTokenProvider;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserServiceImpl userService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User user) throws Exception {
        Authentication authentication = authentication(user.getUsername(), user.getPassword());
        AuthResponse response = new AuthResponse();
        try {
            final UserDetails userDetails = userService.loadUserByUsername(user.getUsername());
            System.out.println("User Detail " + userDetails.getUsername());
            Map<String, String> map = jwtTokenProvider.generateToken(authentication);
            response.setAccessToken(map.get("accessToken"));
            response.setExpiredIn(map.get("expiredIn"));
            response.setRefreshToken(map.get("refreshToken"));
        } catch (JsonProcessingException ex) {
            throw new BadCredentialsException("Bad Login Credentials");
        } catch (AuthenticationException ex) {
            log.info("Invalid User Authentication !!!");
            ex.printStackTrace();
        }
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    private Authentication authentication(String username, String password) throws Exception {
        Authentication authentication = null;
        try {
            authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (DisabledException ex) {
            log.info(" User Disabled !!");
            throw new Exception("USER_DISABLED", ex);
        } catch (BadCredentialsException ex) {
            log.error("Invalid Credential !!!");
            throw new Exception("INVALID_CREDENTIAL");
        }
        return authentication;
    }
}
