package com.enterprise.vulnusermanager.service;

import com.enterprise.vulnusermanager.entity.User;
import com.enterprise.vulnusermanager.repository.UserRepository;
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

    /**
     * Save a new user to the database
     * No password hashing - stored as plain text
     * @param user the user to save
     * @return the saved user
     */
    @Transactional
    public User saveUser(User user) {
        log.info("Saving user: {}", user.getUsername());
        // No password encryption - intentionally vulnerable
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

}
