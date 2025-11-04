package com.enterprise.vulnusermanager.controller;

import com.enterprise.vulnusermanager.entity.User;
import com.enterprise.vulnusermanager.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * FinanceController
 * VULNERABLE: CWE-352 Cross-Site Request Forgery (CSRF)
 * Demonstrates CSRF vulnerability through state-changing operations without token validation
 * CSRF protection is DISABLED in SecurityConfig
 * INTENTIONALLY VULNERABLE for SAST detection
 */
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Slf4j
public class FinanceController {

    private final UserService userService;

    /**
     * VULNERABLE: Transfer Funds Endpoint (CWE-352)
     * Performs state-changing operation (fund transfer) without CSRF token validation
     * CSRF protection is disabled in SecurityConfig
     * NO authentication or authorization required
     * INTENTIONALLY VULNERABLE for SAST detection
     * @param request JSON containing fromUserId, toUserId, and amount
     * @return success message with updated balances
     */
    @PostMapping("/transfer-funds")
    public ResponseEntity<Map<String, Object>> transferFunds(@RequestBody Map<String, Object> request) {
        Long fromUserId = ((Number) request.get("fromUserId")).longValue();
        Long toUserId = ((Number) request.get("toUserId")).longValue();
        Double amount = ((Number) request.get("amount")).doubleValue();

        log.info("POST /api/transfer-funds - Transferring {} from user {} to user {}", amount, fromUserId, toUserId);
        log.warn("SECURITY WARNING: CSRF protection disabled - CWE-352 CSRF vulnerability!");
        log.warn("SECURITY WARNING: No authentication or session validation!");

        // VULNERABLE: No CSRF token check
        // VULNERABLE: No authentication check
        // VULNERABLE: No authorization check

        User fromUser = userService.findUserById(fromUserId)
                .orElseThrow(() -> new RuntimeException("Source user not found"));
        User toUser = userService.findUserById(toUserId)
                .orElseThrow(() -> new RuntimeException("Destination user not found"));

        // Perform transfer without any security checks
        fromUser.setBalance(fromUser.getBalance() - amount);
        toUser.setBalance(toUser.getBalance() + amount);

        userService.saveUser(fromUser);
        userService.saveUser(toUser);

        log.warn("Transfer completed WITHOUT CSRF protection or authentication!");

        return ResponseEntity.ok(Map.of(
                "message", "Transfer successful (no CSRF protection)",
                "fromUser", fromUser.getUsername(),
                "toUser", toUser.getUsername(),
                "amount", amount,
                "fromUserBalance", fromUser.getBalance(),
                "toUserBalance", toUser.getBalance()
        ));
    }

}
