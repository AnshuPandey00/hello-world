package com.enterprise.vulnusermanager.controller;

import com.enterprise.vulnusermanager.entity.User;
import com.enterprise.vulnusermanager.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * AdminController
 * VULNERABLE: CWE-269 Improper Privilege Management
 * Demonstrates improper privilege management through flawed role checking
 * INTENTIONALLY VULNERABLE for SAST detection
 */
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Slf4j
public class AdminController {

    private final UserService userService;

    /**
     * VULNERABLE: Improper Privilege Management (CWE-269)
     * Admin-only endpoint with flawed role check
     * Uses manual if statement instead of Spring Security @PreAuthorize
     * Bypasses Spring Security's role-based access control
     * INTENTIONALLY VULNERABLE for SAST detection
     * @param userId the user ID to check for admin role
     * @param action the admin action to perform
     * @return response indicating if action was allowed
     */
    @PostMapping("/admin-only")
    public ResponseEntity<Map<String, Object>> adminOnlyAction(
            @RequestParam Long userId,
            @RequestBody Map<String, String> action) {

        log.info("POST /api/admin-only - VULNERABLE Improper Privilege Management endpoint");
        log.warn("SECURITY WARNING: Manual role check bypassing Spring Security - CWE-269 Improper Privilege Management!");

        Map<String, Object> result = new HashMap<>();

        // VULNERABLE: Manual role check without Spring Security integration
        // No @PreAuthorize annotation, no proper authorization framework
        User user = userService.findUserById(userId).orElse(null);

        if (user == null) {
            result.put("authorized", false);
            result.put("error", "User not found");
            return ResponseEntity.badRequest().body(result);
        }

        log.warn("VULNERABLE: Checking role with simple if statement: user.getRole().equals(\"ADMIN\")");

        // VULNERABLE: Simple string comparison without Spring Security
        // No integration with security context, easily bypassed
        if (user.getRole().equals("ADMIN")) {
            log.warn("SECURITY WARNING: Role check passed WITHOUT Spring Security @PreAuthorize!");
            result.put("authorized", true);
            result.put("message", "Admin action executed");
            result.put("action", action.get("action"));
            result.put("userId", userId);
            result.put("role", user.getRole());
            result.put("vulnerability", "CWE-269: Manual role check without Spring Security integration");
        } else {
            log.warn("Role check failed: User is not ADMIN");
            result.put("authorized", false);
            result.put("message", "User is not authorized - not an admin");
            result.put("role", user.getRole());
        }

        return ResponseEntity.ok(result);
    }

}
