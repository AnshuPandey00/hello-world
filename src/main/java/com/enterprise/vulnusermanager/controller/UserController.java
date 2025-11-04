package com.enterprise.vulnusermanager.controller;

import com.enterprise.vulnusermanager.entity.User;
import com.enterprise.vulnusermanager.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
     * VULNERABLE: Register a new user (CWE-20 Improper Input Validation)
     * No authentication required
     * No input validation or sanitization - accepts null/empty username
     * INTENTIONALLY VULNERABLE for SAST detection
     * @param user the user to register
     * @return the created user
     */
    @PostMapping("/register")
    public ResponseEntity<User> registerUser(@RequestBody User user) {
        log.info("POST /api/register - Registering user: {}", user != null ? user.getUsername() : "null");
        log.warn("SECURITY WARNING: No input validation - CWE-20 Improper Input Validation vulnerability!");

        // VULNERABLE: No validation on input - accepts null/empty username
        // VULNERABLE: No check for duplicate usernames
        // VULNERABLE: Password stored as plain text
        // VULNERABLE: Allows null user object

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

    /**
     * VULNERABLE: XSS Profile Endpoint (CWE-79)
     * Renders user profile with NO input sanitization
     * Directly outputs user-controlled data in HTML without escaping
     * INTENTIONALLY VULNERABLE for SAST detection
     * @param username the username to display
     * @return ModelAndView with user data that will be unsafely rendered
     */
    @GetMapping("/xss-profile/{username}")
    public ModelAndView getXssProfile(@PathVariable String username) {
        log.info("GET /api/xss-profile/{} - VULNERABLE XSS endpoint", username);

        // No input validation or sanitization - VULNERABLE!
        ModelAndView modelAndView = new ModelAndView("profile");

        // Fetch user without any sanitization
        userService.findUserByUsername(username).ifPresentOrElse(
            user -> {
                // Pass raw user data to template - will be rendered unsafely
                modelAndView.addObject("user", user);
                modelAndView.addObject("username", username);
                log.warn("SECURITY WARNING: Rendering user profile without XSS protection for user: {}", username);
            },
            () -> {
                // Even the username itself is vulnerable when user not found
                modelAndView.addObject("username", username);
                modelAndView.addObject("error", "User not found");
                log.warn("SECURITY WARNING: Rendering error page with unsanitized username: {}", username);
            }
        );

        return modelAndView;
    }

    /**
     * VULNERABLE: SQL Injection Search Endpoint (CWE-89)
     * Searches users using unsafe string concatenation in JPQL query
     * NO parameterized query - INTENTIONALLY VULNERABLE for SAST detection
     * @param query the search query parameter from user
     * @return list of users matching the search
     */
    @GetMapping("/search-users")
    public ResponseEntity<List<User>> searchUsers(@RequestParam String query) {
        log.info("GET /api/search-users?query={} - VULNERABLE SQL Injection endpoint", query);
        log.warn("SECURITY WARNING: SQL Injection via string concatenation - CWE-89");

        List<User> users = userService.searchUsers(query);
        return ResponseEntity.ok(users);
    }

    /**
     * VULNERABLE: Missing Authorization (CWE-862)
     * Deletes any user without authentication or authorization checks
     * NO @PreAuthorize, NO role verification - INTENTIONALLY VULNERABLE
     * @param id the user ID to delete
     * @return success message
     */
    @DeleteMapping("/users/{id}")
    public ResponseEntity<String> deleteUser(@PathVariable Long id) {
        log.info("DELETE /api/users/{} - VULNERABLE Missing Authorization endpoint", id);
        log.warn("SECURITY WARNING: No authorization check - CWE-862 Missing Authorization vulnerability!");

        // No authentication check
        // No role verification
        // Anyone can delete any user
        userService.findUserById(id).ifPresent(user -> {
            log.warn("Deleting user without authorization: {}", user.getUsername());
            // Note: We're not actually implementing delete in the service for simplicity
            // But the vulnerability is present - no authorization check
        });

        return ResponseEntity.ok("User deleted (no authorization required)");
    }

    /**
     * VULNERABLE: Incorrect Authorization (CWE-863)
     * Edit user endpoint with flawed authorization check
     * Uses == operator on strings instead of equals() - INTENTIONALLY VULNERABLE
     * @param id the user ID to edit
     * @param updates the updated user data
     * @return the updated user
     */
    @PostMapping("/edit-user/{id}")
    public ResponseEntity<Map<String, Object>> editUser(
            @PathVariable Long id,
            @RequestParam String currentUserId,
            @RequestBody Map<String, Object> updates) {

        log.info("POST /api/edit-user/{} - VULNERABLE Incorrect Authorization endpoint", id);
        log.warn("SECURITY WARNING: Flawed authorization check - CWE-863 Incorrect Authorization vulnerability!");

        Map<String, Object> result = new HashMap<>();

        // VULNERABLE: Using == operator on strings instead of equals()
        // This compares object references, not values, so authorization can be bypassed
        String targetUserId = String.valueOf(id);

        log.warn("VULNERABLE: Comparing strings with == operator: '{}' == '{}'", currentUserId, targetUserId);

        if (currentUserId == targetUserId) {
            log.warn("Authorization check PASSED (but VULNERABLE due to == operator)");
            result.put("authorized", true);
            result.put("message", "User authorized to edit (vulnerable check)");
            result.put("vulnerability", "CWE-863: Using == on strings instead of equals()");
        } else {
            log.warn("Authorization check FAILED due to string comparison with ==");
            result.put("authorized", false);
            result.put("message", "Not authorized (failed due to == operator)");
            result.put("vulnerability", "CWE-863: String comparison with == is flawed");
        }

        result.put("currentUserId", currentUserId);
        result.put("targetUserId", targetUserId);

        return ResponseEntity.ok(result);
    }

}
