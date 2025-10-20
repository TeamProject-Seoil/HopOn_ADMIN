package com.example.backend.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class AuthRequest {
    @NotBlank private String userid;
    @NotBlank private String password;
    @NotBlank private String clientType;  // USER_APP | DRIVER_APP | ADMIN_APP
    @NotBlank private String deviceId;    // 기기 고유값(앱에서 생성/보관)
}
