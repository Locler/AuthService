package com.dtos;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class LoginRequest {

    @NotBlank
    @Size(min=3,max = 50, message = "Username cannot be longer than 50 characters")
    private String username;

    @NotBlank
    @Size(min = 4, max = 64)
    private String password;
}
