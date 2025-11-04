package com.enterprise.vulnusermanager.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * SerializeController
 * VULNERABLE: CWE-502 Deserialization of Untrusted Data
 * Demonstrates unsafe deserialization of user-provided data
 * INTENTIONALLY VULNERABLE for SAST detection
 */
@RestController
@RequestMapping("/api")
@Slf4j
public class SerializeController {

    /**
     * VULNERABLE: Unsafe Deserialization Endpoint (CWE-502)
     * Deserializes user-provided base64-encoded byte array
     * Uses ObjectInputStream without validation - INTENTIONALLY VULNERABLE
     * Allows arbitrary object deserialization leading to RCE
     * @param request JSON containing base64-encoded serialized object
     * @return deserialization result as JSON
     */
    @PostMapping("/deserialize-object")
    public ResponseEntity<Map<String, Object>> deserializeObject(@RequestBody Map<String, String> request) {
        String base64Data = request.get("data");

        log.info("POST /api/deserialize-object - VULNERABLE Unsafe Deserialization endpoint");
        log.warn("SECURITY WARNING: Deserializing untrusted data - CWE-502 Deserialization of Untrusted Data vulnerability!");

        Map<String, Object> result = new HashMap<>();

        try {
            // VULNERABLE: Deserializing user-provided data without validation
            // This can lead to Remote Code Execution (RCE) through gadget chains
            byte[] data = Base64.getDecoder().decode(base64Data);

            log.warn("VULNERABLE: Creating ObjectInputStream with user-provided data!");
            log.warn("VULNERABLE: No type checking, no whitelist, no validation!");

            // VULNERABLE: Unsafe deserialization
            ByteArrayInputStream byteStream = new ByteArrayInputStream(data);
            ObjectInputStream objectInputStream = new ObjectInputStream(byteStream);

            // This can execute arbitrary code through deserialization gadgets
            Object deserializedObject = objectInputStream.readObject();

            objectInputStream.close();

            result.put("success", true);
            result.put("objectType", deserializedObject.getClass().getName());
            result.put("objectValue", deserializedObject.toString());
            result.put("warning", "Object deserialized without validation - CWE-502");

            log.warn("Object deserialized WITHOUT validation: {}", deserializedObject.getClass().getName());

            return ResponseEntity.ok(result);

        } catch (Exception e) {
            log.error("Error deserializing object: {}", e.getMessage());
            result.put("success", false);
            result.put("error", "Error deserializing object: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(result);
        }
    }

}
