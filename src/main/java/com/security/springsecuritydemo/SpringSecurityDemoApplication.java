package com.security.springsecuritydemo;

import com.security.springsecuritydemo.enums.UserRole;
import com.security.springsecuritydemo.model.User;
import com.security.springsecuritydemo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@SpringBootApplication
public class SpringSecurityDemoApplication implements CommandLineRunner {
    
    @Autowired
    private UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityDemoApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        String superAdmin = "superAdmin";
        Optional<User> user = userRepository.findByUsername(superAdmin);
        if(!user.isPresent()) {
            User superUser = new User();
            Set<UserRole> roles = new HashSet<>();
            roles.add(UserRole.ADMIN);
            roles.add(UserRole.USER);
            superUser.setUsername("superAdmin");
            superUser.setPassword(passwordEncoder.encode("superAdmin"));
            superUser.setRoles(roles);
            userRepository.save(superUser);
        }
    }
}
