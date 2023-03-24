package com.security.springsecuritydemo.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("hello")
    public ResponseEntity<?> hello() {
        System.out.println("Hello");
        try {
            new ResponseEntity<>("Hello", HttpStatus.OK);
        } catch (Exception ex) {
            System.out.println("Exception from Hello : "+ex);
        }
        return new ResponseEntity<>("Hello", HttpStatus.OK);
    }

    @GetMapping("bye")
    public ResponseEntity<?> bye() {
        System.out.println("Bye");
        try {
            new ResponseEntity<>("Hello", HttpStatus.OK);
        } catch (Exception ex) {
            System.out.println("Exception from Hello : "+ex);
        }
        return new ResponseEntity<>("Bye", HttpStatus.OK);
    }
}
