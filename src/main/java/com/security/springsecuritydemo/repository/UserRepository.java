package com.security.springsecuritydemo.repository;

import com.security.springsecuritydemo.model.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    @Query(value = "select * from user where username = ?1", nativeQuery = true)
//    @EntityGraph(attributePaths = {"roles"})
    Optional<User> findByUsername(String username);
}
