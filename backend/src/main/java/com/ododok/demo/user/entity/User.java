package com.ododok.demo.user.entity;

import lombok.*;
import java.time.LocalDateTime;

/**
 * 사용자 정보 엔티티
 * users 테이블과 매핑
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@ToString(exclude = "password") // 비밀번호는 toString에서 제외
public class User {

    private Integer userId;           // 사용자 ID (PK)
    private String email;             // 이메일 (Unique)
    private String password;          // 비밀번호 (소셜로그인시 NULL)
    private String nickname;          // 닉네임
    private String profileUrl;        // 프로필 이미지 URL

    @Builder.Default
    private String provider = "LOCAL";     // 로그인 방식 (LOCAL, NAVER)
    private String providerId;             // 소셜 로그인 제공자 ID

    private LocalDateTime createdAt;  // 생성일시
    private LocalDateTime updatedAt;  // 수정일시

    // 비즈니스 메서드만 남김!

    /**
     * 소셜 로그인 사용자인지 확인
     */
    public boolean isSocialUser() {
        return !"LOCAL".equals(this.provider);
    }

    /**
     * 일반 로그인 사용자인지 확인
     */
    public boolean isLocalUser() {
        return "LOCAL".equals(this.provider);
    }

    /**
     * 비밀번호가 설정되어 있는지 확인
     */
    public boolean hasPassword() {
        return this.password != null && !this.password.trim().isEmpty();
    }

    // 정적 팩토리 메서드 - 일반 회원가입용
    public static User createLocalUser(String email, String password, String nickname) {
        return User.builder()
                .email(email)
                .password(password)
                .nickname(nickname)
                .provider("LOCAL")
                .build();
    }

    // 정적 팩토리 메서드 - 소셜 로그인용
    public static User createSocialUser(String email, String nickname, String provider, String providerId) {
        return User.builder()
                .email(email)
                .nickname(nickname)
                .provider(provider)
                .providerId(providerId)
                .build();
    }
}