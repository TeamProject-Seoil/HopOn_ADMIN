package com.example.backend.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class ChangePasswordRequest {
    @NotBlank private String currentPassword;
    @NotBlank
    @Pattern(regexp = "^[A-Za-z0-9]{10,16}$", message = "새 비밀번호는 10~16자 영문/숫자만 가능합니다.")
    private String newPassword;

}
