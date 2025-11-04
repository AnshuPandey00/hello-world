package com.enterprise.vulnusermanager.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * SecurityConfig
 * Spring Security Configuration
 * VULNERABLE: CWE-352 Cross-Site Request Forgery (CSRF)
 * CSRF protection is DISABLED - exposes state-changing operations to CSRF attacks
 * INTENTIONALLY VULNERABLE for SAST detection
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Configure security filter chain
     * VULNERABLE: CWE-352 CSRF protection DISABLED
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
            .httpBasic(httpBasic -> {}); // HTTP Basic auth configured but not required

        return http.build();
    }

}
