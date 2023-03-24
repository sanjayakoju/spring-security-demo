package com.security.springsecuritydemo.controller;

import com.security.springsecuritydemo.enums.UserRole;
import com.security.springsecuritydemo.model.User;
import com.security.springsecuritydemo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashSet;
import java.util.Set;

@RestController
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("user-register")
    public ResponseEntity<?> saveUser(@RequestBody User user) {
        Set<UserRole> userRoleSet = new HashSet<>();
        userRoleSet.add(UserRole.USER);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRoles(userRoleSet);
        userRepository.save(user);
        return new ResponseEntity<>(HttpStatus.OK);
    }
}
