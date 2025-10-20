package com.example.backend.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class LogoutRequest {
    @NotBlank private String clientType;
    @NotBlank private String deviceId;
    @NotBlank private String refreshToken;
}
