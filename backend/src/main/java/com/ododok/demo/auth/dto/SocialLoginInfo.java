package com.ododok.demo.auth.dto;

import lombok.*;
import jakarta.validation.constraints.*;

/**
 * 소셜 로그인 콜백 정보 DTO
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
class SocialLoginInfo {

    @NotBlank
    private String email;

    @NotBlank
    private String nickname;

    @NotBlank
    private String provider; // NAVER, GOOGLE 등

    @NotBlank
    private String providerId; // 소셜 로그인 제공자의 사용자 ID

    private String profileImageUrl; // 프로필 이미지 URL (선택적)
}
