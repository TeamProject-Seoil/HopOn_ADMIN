// src/main/java/com/example/backend/dto/VerifyPasswordRequest.java
package com.example.backend.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class VerifyPasswordRequest {
    @NotBlank
    private String password;
}
