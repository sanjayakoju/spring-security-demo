package com.security.springsecuritydemo.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("hello")
    public ResponseEntity<?> hello() {
        return new ResponseEntity<>("Hello", HttpStatus.OK);
    }
}
