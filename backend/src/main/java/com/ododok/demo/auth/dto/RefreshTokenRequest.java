package com.ododok.demo.auth.dto;

import lombok.*;
import jakarta.validation.constraints.*;

/**
 * 토큰 갱신 요청 DTO
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
class RefreshTokenRequest {

    @NotBlank(message = "리프레시 토큰은 필수입니다.")
    private String refreshToken;
}
