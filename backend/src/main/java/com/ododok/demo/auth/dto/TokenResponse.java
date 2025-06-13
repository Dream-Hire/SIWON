package com.ododok.demo.auth.dto;

import lombok.*;
import jakarta.validation.constraints.NotNull;

/**
 * 토큰 응답 DTO
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TokenResponse {

    @NotNull
    private String accessToken;

    @NotNull
    private String refreshToken;

    @Builder.Default
    private String tokenType = "Bearer";

    private Long expiresIn; // 액세스 토큰 만료까지 남은 시간 (초)

    // 사용자 정보도 함께 반환
    private UserInfo user;

    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class UserInfo {
        private Integer userId;
        private String email;
        private String nickname;
        private String profileUrl;
        private String provider;
    }

    /**
     * 사용자 정보와 함께 토큰 응답 생성
     */
    public static TokenResponse of(String accessToken, String refreshToken,
                                   com.ododok.demo.user.entity.User user) {
        UserInfo userInfo = UserInfo.builder()
                .userId(user.getUserId())
                .email(user.getEmail())
                .nickname(user.getNickname())
                .profileUrl(user.getProfileUrl())
                .provider(user.getProvider())
                .build();

        return TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(1800L) // 30분 (초 단위)
                .user(userInfo)
                .build();
    }
}