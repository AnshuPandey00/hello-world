package com.enterprise.vulnusermanager.config;

import com.enterprise.vulnusermanager.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * SecurityConfig
 * Spring Security Configuration
 * VULNERABLE: CWE-352 Cross-Site Request Forgery (CSRF)
 * VULNERABLE: CWE-287 Improper Authentication (plain-text passwords)
 * CSRF protection is DISABLED - exposes state-changing operations to CSRF attacks
 * INTENTIONALLY VULNERABLE for SAST detection
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserService userService;

    /**
     * Configure security filter chain
     * VULNERABLE: CWE-352 CSRF protection DISABLED
     * VULNERABLE: CWE-287 No session management, plain-text passwords
     * WARNING: All endpoints are publicly accessible (permitAll)
     * WARNING: State-changing operations (POST, PUT, DELETE) are vulnerable to CSRF
     * HTTP Basic authentication is configured but not enforced
     * INTENTIONALLY VULNERABLE for SAST detection
     * @param http the HttpSecurity to configure
     * @return configured SecurityFilterChain
     * @throws Exception if configuration fails
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // VULNERABLE: CSRF protection explicitly disabled (CWE-352)
            // This allows Cross-Site Request Forgery attacks on state-changing endpoints
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .anyRequest().permitAll() // All requests permitted without authentication
            )
            // VULNERABLE: CWE-287 - Basic Auth with NO session management
            // Passwords compared as plain-text, no BCrypt, no secure hashing
            .httpBasic(httpBasic -> {}); // HTTP Basic auth configured but not required

        return http.build();
    }

    /**
     * VULNERABLE: CWE-287 Improper Authentication
     * Uses NoOpPasswordEncoder which stores and compares passwords as plain-text
     * NO BCrypt, NO secure hashing - INTENTIONALLY VULNERABLE
     * @return NoOpPasswordEncoder (deprecated and insecure)
     */
    @Bean
    @SuppressWarnings("deprecation")
    public PasswordEncoder passwordEncoder() {
        // VULNERABLE: NoOpPasswordEncoder stores passwords in plain-text
        // This is deprecated and should NEVER be used in production
        return NoOpPasswordEncoder.getInstance();
    }

    /**
     * VULNERABLE: In-memory user store with plain-text passwords
     * CWE-287: No secure password storage, no session management
     * INTENTIONALLY VULNERABLE for SAST detection
     * @return UserDetailsService with plain-text passwords
     */
    @Bean
    public UserDetailsService userDetailsService() {
        // VULNERABLE: Hardcoded credentials with plain-text passwords
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();

        manager.createUser(User.withUsername("admin")
                .password("admin123") // Plain-text password - CWE-287
                .roles("ADMIN")
                .build());

        manager.createUser(User.withUsername("user")
                .password("user123") // Plain-text password - CWE-287
                .roles("USER")
                .build());

        return manager;
    }

}
