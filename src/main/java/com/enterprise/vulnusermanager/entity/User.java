package com.enterprise.vulnusermanager.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * User Entity
 * Represents a user in the system with basic authentication information
 */
@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    /**
     * Password stored in plain text
     * WARNING: This is intentionally insecure for demonstration purposes
     */
    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String email;

    /**
     * User role: "ADMIN" or "USER"
     */
    @Column(nullable = false)
    private String role;

    /**
     * User account balance
     * Used for demonstrating CSRF vulnerability (CWE-352)
     */
    @Column(nullable = false)
    private Double balance = 0.0;

}
