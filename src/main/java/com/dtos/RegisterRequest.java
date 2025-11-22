package com.dtos;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.*;


@Data
public class RegisterRequest {

    @NotNull
    private Long userId;

    @NotBlank
    @Size(min=3,max = 50, message = "Username cannot be longer than 50 characters")
    private String username;

    @NotBlank
    @Size(min = 4, max = 64, message = "Password must be between 4 and 64 characters")
    private String password;

    @NotBlank
    private String role;
}

