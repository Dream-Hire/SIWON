package com.ododok.demo.auth.entity;

import lombok.*;
import java.time.LocalDateTime;

/**
 * 리프레시 토큰 엔티티
 * refresh_tokens 테이블과 매핑
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@ToString(exclude = "token") // 보안상 토큰 전체는 로그에 노출하지 않음
public class RefreshToken {

    private Long id;                    // 리프레시 토큰 ID (PK)
    private Integer userId;             // 사용자 ID (FK)
    private String token;               // 리프레시 토큰 값
    private LocalDateTime expiresAt;    // 만료 시간
    private LocalDateTime createdAt;    // 생성 시간

    // 비즈니스 메서드

    /**
     * 토큰이 만료되었는지 확인
     */
    public boolean isExpired() {
        return LocalDateTime.now().isAfter(this.expiresAt);
    }

    /**
     * 토큰이 유효한지 확인 (만료되지 않았는지)
     */
    public boolean isValid() {
        return !isExpired();
    }

    /**
     * 정적 팩토리 메서드 - 새 리프레시 토큰 생성
     */
    public static RefreshToken create(Integer userId, String token, LocalDateTime expiresAt) {
        return RefreshToken.builder()
                .userId(userId)
                .token(token)
                .expiresAt(expiresAt)
                .build();
    }
}