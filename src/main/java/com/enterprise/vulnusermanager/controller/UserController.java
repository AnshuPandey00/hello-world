package com.enterprise.vulnusermanager.controller;

import com.enterprise.vulnusermanager.entity.User;
import com.enterprise.vulnusermanager.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * UserController
 * REST API endpoints for user management
 * No authentication or input validation
 */
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final UserService userService;

    /**
     * Get all users
     * No authentication required - openly accessible
     * @return list of all users with plain text passwords
     */
    @GetMapping("/users")
    public ResponseEntity<List<User>> getAllUsers() {
        log.info("GET /api/users - Fetching all users");
        List<User> users = userService.findAllUsers();
        return ResponseEntity.ok(users);
    }

    /**
     * Register a new user
     * No authentication required
     * No input validation or sanitization
     * @param user the user to register
     * @return the created user
     */
    @PostMapping("/register")
    public ResponseEntity<User> registerUser(@RequestBody User user) {
        log.info("POST /api/register - Registering user: {}", user.getUsername());

        // No validation on input
        // No check for duplicate usernames
        // Password stored as plain text

        User savedUser = userService.saveUser(user);
        return ResponseEntity.status(HttpStatus.CREATED).body(savedUser);
    }

    /**
     * Get user by ID
     * No authentication required
     * @param id the user ID
     * @return the user if found
     */
    @GetMapping("/users/{id}")
    public ResponseEntity<User> getUserById(@PathVariable Long id) {
        log.info("GET /api/users/{} - Fetching user by ID", id);
        return userService.findUserById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

}
