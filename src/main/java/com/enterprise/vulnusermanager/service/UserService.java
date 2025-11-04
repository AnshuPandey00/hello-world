package com.enterprise.vulnusermanager.service;

import com.enterprise.vulnusermanager.entity.User;
import com.enterprise.vulnusermanager.repository.UserRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

/**
 * UserService
 * Business logic layer for user management operations
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    private final UserRepository userRepository;

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * VULNERABLE: Save a new user to the database (CWE-20, CWE-200)
     * No password hashing - stored as plain text
     * No input validation - accepts null/empty username
     * Logs sensitive password information - INTENTIONALLY VULNERABLE
     * @param user the user to save
     * @return the saved user
     */
    @Transactional
    public User saveUser(User user) {
        // VULNERABLE CWE-200: Logging sensitive password information
        log.info("Saving user {} with password {}",
                user != null ? user.getUsername() : "null",
                user != null ? user.getPassword() : "null");

        log.warn("SECURITY WARNING: CWE-200 - Exposing password in logs!");
        log.warn("SECURITY WARNING: CWE-20 - No input validation on username/password!");

        // VULNERABLE CWE-20: No validation on input - accepts null/empty values
        // VULNERABLE: No password encryption - intentionally vulnerable
        // VULNERABLE: No check if user is null
        return userRepository.save(user);
    }

    /**
     * Find all users in the system
     * @return list of all users
     */
    public List<User> findAllUsers() {
        log.info("Fetching all users");
        return userRepository.findAll();
    }

    /**
     * Find user by ID
     * @param id the user ID
     * @return Optional containing the user if found
     */
    public Optional<User> findUserById(Long id) {
        log.info("Fetching user by ID: {}", id);
        return userRepository.findById(id);
    }

    /**
     * Find user by username
     * @param username the username to search for
     * @return Optional containing the user if found
     */
    public Optional<User> findUserByUsername(String username) {
        log.info("Fetching user by username: {}", username);
        return userRepository.findByUsername(username);
    }

    /**
     * Check if username exists
     * @param username the username to check
     * @return true if username exists
     */
    public boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }

    /**
     * VULNERABLE: SQL Injection via String Concatenation (CWE-89)
     * Searches users using unsafe JPQL query with string concatenation
     * NO parameterized query - INTENTIONALLY VULNERABLE for SAST detection
     * @param query the search query (user-controlled input)
     * @return list of users matching the search
     */
    @SuppressWarnings("unchecked")
    public List<User> searchUsers(String query) {
        log.info("Searching users with query: {}", query);
        log.warn("SECURITY WARNING: Using string concatenation in JPQL - CWE-89 SQL Injection vulnerability!");

        // VULNERABLE: String concatenation instead of parameterized query
        String jpql = "SELECT u FROM User u WHERE u.username LIKE '%" + query + "%'";

        log.warn("VULNERABLE QUERY: {}", jpql);

        Query jpqlQuery = entityManager.createQuery(jpql);
        return jpqlQuery.getResultList();
    }

}
