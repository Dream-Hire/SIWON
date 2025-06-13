package com.ododok.demo.user.service;

import com.ododok.demo.user.entity.User;
import com.ododok.demo.user.mapper.UserMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/**
 * 사용자 관리 서비스
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserService {

    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;

    /**
     * 사용자 ID로 조회
     * @param userId 사용자 ID
     * @return 사용자 정보
     */
    public Optional<User> findById(Integer userId) {
        return userMapper.findById(userId);
    }

    /**
     * 이메일로 사용자 조회
     * @param email 이메일
     * @return 사용자 정보
     */
    public Optional<User> findByEmail(String email) {
        return userMapper.findByEmail(email);
    }

    /**
     * 소셜 로그인 사용자 조회
     * @param provider 소셜 로그인 제공자
     * @param providerId 제공자 사용자 ID
     * @return 사용자 정보
     */
    public Optional<User> findByProviderAndProviderId(String provider, String providerId) {
        return userMapper.findByProviderAndProviderId(provider, providerId);
    }

    /**
     * 이메일 중복 체크
     * @param email 이메일
     * @return 중복이면 true
     */
    public boolean isEmailExists(String email) {
        return userMapper.existsByEmail(email);
    }

    /**
     * 닉네임 중복 체크
     * @param nickname 닉네임
     * @return 중복이면 true
     */
    public boolean isNicknameExists(String nickname) {
        return userMapper.existsByNickname(nickname);
    }

    /**
     * 사용자 정보 수정
     * @param user 수정할 사용자 정보
     * @return 수정된 사용자 정보
     */
    @Transactional
    public User updateUser(User user) {
        // 닉네임 중복 체크 (자신은 제외)
        if (isNicknameExistsExceptSelf(user.getUserId(), user.getNickname())) {
            throw new IllegalArgumentException("이미 사용 중인 닉네임입니다.");
        }

        int updatedRows = userMapper.updateUser(user);
        if (updatedRows == 0) {
            throw new IllegalArgumentException("사용자를 찾을 수 없습니다.");
        }

        log.info("사용자 정보 수정 완료: userId={}", user.getUserId());
        return findById(user.getUserId())
                .orElseThrow(() -> new IllegalArgumentException("수정된 사용자 정보를 찾을 수 없습니다."));
    }

    /**
     * 비밀번호 변경
     * @param userId 사용자 ID
     * @param currentPassword 현재 비밀번호
     * @param newPassword 새 비밀번호
     */
    @Transactional
    public void changePassword(Integer userId, String currentPassword, String newPassword) {
        User user = findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));

        // 일반 로그인 사용자만 비밀번호 변경 가능
        if (!user.isLocalUser()) {
            throw new IllegalArgumentException("소셜 로그인 사용자는 비밀번호를 변경할 수 없습니다.");
        }

        // 현재 비밀번호 확인
        if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
            throw new IllegalArgumentException("현재 비밀번호가 올바르지 않습니다.");
        }

        // 새 비밀번호 암호화 및 저장
        String encodedNewPassword = passwordEncoder.encode(newPassword);
        int updatedRows = userMapper.updatePassword(userId, encodedNewPassword);

        if (updatedRows == 0) {
            throw new IllegalArgumentException("비밀번호 변경에 실패했습니다.");
        }

        log.info("비밀번호 변경 완료: userId={}", userId);
    }

    /**
     * 프로필 이미지 URL 업데이트
     * @param userId 사용자 ID
     * @param profileUrl 새 프로필 이미지 URL
     */
    @Transactional
    public void updateProfileUrl(Integer userId, String profileUrl) {
        int updatedRows = userMapper.updateProfileUrl(userId, profileUrl);
        if (updatedRows == 0) {
            throw new IllegalArgumentException("사용자를 찾을 수 없습니다.");
        }

        log.info("프로필 이미지 업데이트 완료: userId={}, profileUrl={}", userId, profileUrl);
    }

    /**
     * 소셜 계정 연동
     * @param userId 사용자 ID
     * @param provider 소셜 로그인 제공자
     * @param providerId 제공자 사용자 ID
     */
    @Transactional
    public void linkSocialAccount(Integer userId, String provider, String providerId) {
        // 해당 소셜 계정이 이미 다른 사용자와 연동되어 있는지 확인
        Optional<User> existingUser = findByProviderAndProviderId(provider, providerId);
        if (existingUser.isPresent() && !existingUser.get().getUserId().equals(userId)) {
            throw new IllegalArgumentException("이미 다른 계정과 연동된 소셜 계정입니다.");
        }

        int updatedRows = userMapper.linkSocialAccount(userId, provider, providerId);
        if (updatedRows == 0) {
            throw new IllegalArgumentException("사용자를 찾을 수 없습니다.");
        }

        log.info("소셜 계정 연동 완료: userId={}, provider={}", userId, provider);
    }

    /**
     * 회원 탈퇴
     * @param userId 사용자 ID
     * @param password 비밀번호 (일반 사용자의 경우)
     */
    @Transactional
    public void deleteUser(Integer userId, String password) {
        User user = findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));

        // 일반 사용자의 경우 비밀번호 확인
        if (user.isLocalUser() && user.hasPassword()) {
            if (password == null || !passwordEncoder.matches(password, user.getPassword())) {
                throw new IllegalArgumentException("비밀번호가 올바르지 않습니다.");
            }
        }

        int deletedRows = userMapper.deleteUser(userId);
        if (deletedRows == 0) {
            throw new IllegalArgumentException("회원 탈퇴에 실패했습니다.");
        }

        log.info("회원 탈퇴 완료: userId={}, provider={}", userId, user.getProvider());
    }

    /**
     * 닉네임 중복 체크 (자신은 제외)
     */
    private boolean isNicknameExistsExceptSelf(Integer userId, String nickname) {
        return userMapper.findByEmail(nickname)
                .map(user -> !user.getUserId().equals(userId))
                .orElse(false);
    }
}