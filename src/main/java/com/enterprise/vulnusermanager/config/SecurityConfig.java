package com.enterprise.vulnusermanager.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * SecurityConfig
 * Spring Security Configuration
 * Currently permits all requests - to be secured later
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Configure security filter chain
     * WARNING: All endpoints are publicly accessible (permitAll)
     * HTTP Basic authentication is configured but not enforced
     * @param http the HttpSecurity to configure
     * @return configured SecurityFilterChain
     * @throws Exception if configuration fails
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // CSRF protection disabled
            .authorizeHttpRequests(auth -> auth
                .anyRequest().permitAll() // All requests permitted without authentication
            )
            .httpBasic(httpBasic -> {}); // HTTP Basic auth configured but not required

        return http.build();
    }

}
