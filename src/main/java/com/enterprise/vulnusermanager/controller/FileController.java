package com.enterprise.vulnusermanager.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

/**
 * FileController
 * VULNERABLE: CWE-22 Path Traversal & CWE-434 Unrestricted File Upload
 * Demonstrates multiple file-related vulnerabilities
 * INTENTIONALLY VULNERABLE for SAST detection
 */
@RestController
@RequestMapping("/api")
@Slf4j
public class FileController {

    private static final String UPLOAD_DIR = "/app/uploads/";

    /**
     * VULNERABLE: Path Traversal Endpoint (CWE-22)
     * Downloads files without path validation or canonicalization
     * Allows directory traversal attacks (e.g., ../../etc/passwd)
     * NO path sanitization - INTENTIONALLY VULNERABLE for SAST detection
     * @param path the file path from user input (user-controlled)
     * @return file contents as byte array
     */
    @GetMapping("/download-file")
    public ResponseEntity<byte[]> downloadFile(@RequestParam String path) {
        log.info("GET /api/download-file?path={} - VULNERABLE Path Traversal endpoint", path);
        log.warn("SECURITY WARNING: No path validation - CWE-22 Path Traversal vulnerability!");

        try {
            // VULNERABLE: Direct concatenation without canonicalization or validation
            // Allows path traversal attacks like "../../etc/passwd"
            String fullPath = UPLOAD_DIR + path;
            log.warn("VULNERABLE: Accessing file at: {}", fullPath);

            // VULNERABLE: Uses FileInputStream without path validation
            File file = new File(fullPath);
            FileInputStream fis = new FileInputStream(file);
            byte[] fileBytes = fis.readAllBytes();
            fis.close();

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
            headers.setContentDispositionFormData("attachment", path);

            log.warn("Successfully served file without path validation!");
            return new ResponseEntity<>(fileBytes, headers, HttpStatus.OK);

        } catch (IOException e) {
            log.error("Error reading file: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(("Error reading file: " + e.getMessage()).getBytes());
        }
    }

    /**
     * VULNERABLE: Unrestricted File Upload Endpoint (CWE-434)
     * Accepts file uploads without extension validation or virus checking
     * Allows uploading dangerous files like .jsp, .jspx, .exe, .sh
     * NO file type validation - INTENTIONALLY VULNERABLE for SAST detection
     * @param file the uploaded file (no validation)
     * @return success message with file location
     */
    @PostMapping("/upload-profile")
    public ResponseEntity<Map<String, String>> uploadProfile(@RequestParam("file") MultipartFile file) {
        log.info("POST /api/upload-profile - VULNERABLE Unrestricted File Upload endpoint");
        log.warn("SECURITY WARNING: No file extension or content validation - CWE-434 Unrestricted File Upload vulnerability!");

        if (file.isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "File is empty"));
        }

        try {
            // VULNERABLE: No file extension validation
            // VULNERABLE: No content type validation
            // VULNERABLE: No virus scanning
            // Allows uploading .jsp, .jspx, .exe, .sh, etc.

            String filename = file.getOriginalFilename();
            log.warn("VULNERABLE: Uploading file without validation: {}", filename);
            log.warn("VULNERABLE: No check for dangerous extensions (.jsp, .jspx, .exe, .sh)");

            // Create upload directory if it doesn't exist
            File uploadDir = new File(UPLOAD_DIR);
            if (!uploadDir.exists()) {
                uploadDir.mkdirs();
            }

            // VULNERABLE: Direct file write without any validation
            Path filePath = Paths.get(UPLOAD_DIR + filename);
            Files.write(filePath, file.getBytes());

            log.warn("File uploaded WITHOUT security validation to: {}", filePath);

            return ResponseEntity.ok(Map.of(
                    "message", "File uploaded successfully (no validation)",
                    "filename", filename,
                    "path", filePath.toString(),
                    "warning", "No extension or virus check performed"
            ));

        } catch (IOException e) {
            log.error("Error uploading file: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Error uploading file: " + e.getMessage()));
        }
    }

}
