package com.security.springsecuritydemo.controller;

import com.security.springsecuritydemo.model.User;
import com.security.springsecuritydemo.security.JWTTokenProvider;
import com.security.springsecuritydemo.security.UserServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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

        final UserDetails userDetails = userService.loadUserByUsername(user.getUsername());
        System.out.println("User Detail "+ userDetails);
        final String token = jwtTokenProvider.generateToken(userDetails);
        System.out.println("Token : "+token);
        return new ResponseEntity<>(token, HttpStatus.OK);
    }

    private Authentication authentication(String username, String password) throws Exception {
        Authentication authentication;
        try {
            authentication= authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (DisabledException ex) {
            throw new Exception("USER_DISABLED", ex);
        } catch (BadCredentialsException ex) {
            throw new Exception("INVALID_CREDENTIAL");
        }
        return authentication;
    }
}
