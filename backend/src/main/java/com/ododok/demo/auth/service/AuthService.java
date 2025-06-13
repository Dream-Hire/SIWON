package com.ododok.demo.auth.service;

import com.ododok.demo.auth.entity.RefreshToken;
import com.ododok.demo.auth.mapper.AuthMapper;
import com.ododok.demo.common.util.JwtUtil;
import com.ododok.demo.user.entity.User;
import com.ododok.demo.user.mapper.UserMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * 인증/인가 서비스
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthService {

    private final UserMapper userMapper;
    private final AuthMapper authMapper;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;

    /**
     * 일반 회원가입
     * @param email 이메일
     * @param password 비밀번호
     * @param nickname 닉네임
     * @return 생성된 사용자 정보
     */
    @Transactional
    public User signUp(String email, String password, String nickname) {
        // 이메일 중복 체크
        if (userMapper.existsByEmail(email)) {
            throw new IllegalArgumentException("이미 사용 중인 이메일입니다.");
        }

        // 닉네임 중복 체크
        if (userMapper.existsByNickname(nickname)) {
            throw new IllegalArgumentException("이미 사용 중인 닉네임입니다.");
        }

        // 비밀번호 암호화
        String encodedPassword = passwordEncoder.encode(password);

        // 사용자 생성
        User user = User.createLocalUser(email, encodedPassword, nickname);
        int insertedRows = userMapper.insertUser(user);

        if (insertedRows == 0) {
            throw new RuntimeException("회원가입에 실패했습니다.");
        }

        log.info("회원가입 완료: userId={}, email={}", user.getUserId(), email);
        return user;
    }

    /**
     * 일반 로그인
     * @param email 이메일
     * @param password 비밀번호
     * @return 토큰 정보 (accessToken, refreshToken)
     */
    @Transactional
    public Map<String, String> signIn(String email, String password) {
        // 사용자 조회
        User user = userMapper.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("이메일 또는 비밀번호가 올바르지 않습니다."));

        // 일반 로그인 사용자인지 확인
        if (!user.isLocalUser()) {
            throw new IllegalArgumentException("소셜 로그인으로 가입된 계정입니다.");
        }

        // 비밀번호 확인
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new IllegalArgumentException("이메일 또는 비밀번호가 올바르지 않습니다.");
        }

        // 토큰 생성 및 저장
        return generateAndSaveTokens(user);
    }

    /**
     * 소셜 로그인 (또는 연동)
     * @param email 이메일
     * @param nickname 닉네임
     * @param provider 소셜 로그인 제공자
     * @param providerId 제공자 사용자 ID
     * @return 토큰 정보 (accessToken, refreshToken)
     */
    @Transactional
    public Map<String, String> socialSignIn(String email, String nickname, String provider, String providerId) {
        // 기존 소셜 계정으로 가입된 사용자 확인
        Optional<User> existingUser = userMapper.findByProviderAndProviderId(provider, providerId);

        User user;
        if (existingUser.isPresent()) {
            // 기존 사용자 로그인
            user = existingUser.get();
            log.info("소셜 로그인: userId={}, provider={}", user.getUserId(), provider);
        } else {
            // 이메일로 기존 계정 확인 (계정 연동 가능성)
            Optional<User> userByEmail = userMapper.findByEmail(email);

            if (userByEmail.isPresent()) {
                // 기존 계정에 소셜 계정 연동
                user = userByEmail.get();
                userMapper.linkSocialAccount(user.getUserId(), provider, providerId);
                log.info("소셜 계정 연동: userId={}, provider={}", user.getUserId(), provider);
            } else {
                // 새 사용자 생성
                user = createSocialUser(email, nickname, provider, providerId);
                log.info("소셜 회원가입: userId={}, provider={}", user.getUserId(), provider);
            }
        }

        // 토큰 생성 및 저장
        return generateAndSaveTokens(user);
    }

    /**
     * 토큰 갱신
     * @param refreshToken 리프레시 토큰
     * @return 새로운 토큰 정보 (accessToken, refreshToken)
     */
    @Transactional
    public Map<String, String> refreshTokens(String refreshToken) {
        // 리프레시 토큰 유효성 검증
        if (!jwtUtil.validateToken(refreshToken) || !jwtUtil.isRefreshToken(refreshToken)) {
            throw new IllegalArgumentException("유효하지 않은 리프레시 토큰입니다.");
        }

        // DB에서 토큰 확인
        RefreshToken storedToken = authMapper.findByToken(refreshToken)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 리프레시 토큰입니다."));

        // 토큰 만료 확인
        if (storedToken.isExpired()) {
            authMapper.deleteByToken(refreshToken);
            throw new IllegalArgumentException("만료된 리프레시 토큰입니다.");
        }

        // 사용자 정보 조회
        User user = userMapper.findById(storedToken.getUserId())
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));

        // 기존 토큰 삭제 후 새 토큰 생성
        authMapper.deleteByToken(refreshToken);

        log.info("토큰 갱신: userId={}", user.getUserId());
        return generateAndSaveTokens(user);
    }

    /**
     * 로그아웃
     * @param refreshToken 리프레시 토큰
     */
    @Transactional
    public void signOut(String refreshToken) {
        if (refreshToken != null) {
            authMapper.deleteByToken(refreshToken);
            log.info("로그아웃 완료: token={}", refreshToken.substring(0, 10) + "...");
        }
    }

    /**
     * 전체 로그아웃 (모든 기기에서 로그아웃)
     * @param userId 사용자 ID
     */
    @Transactional
    public void signOutAll(Integer userId) {
        int deletedCount = authMapper.deleteAllByUserId(userId);
        log.info("전체 로그아웃 완료: userId={}, 삭제된 토큰 수={}", userId, deletedCount);
    }

    /**
     * 토큰 검증
     * @param accessToken 액세스 토큰
     * @return 사용자 ID
     */
    public Integer validateAccessToken(String accessToken) {
        if (!jwtUtil.validateToken(accessToken) || !jwtUtil.isAccessToken(accessToken)) {
            throw new IllegalArgumentException("유효하지 않은 액세스 토큰입니다.");
        }

        return jwtUtil.getUserIdFromToken(accessToken);
    }

    /**
     * 만료된 리프레시 토큰 정리 (배치 작업용)
     */
    @Transactional
    public void cleanupExpiredTokens() {
        int deletedCount = authMapper.deleteExpiredTokens(LocalDateTime.now());
        log.info("만료된 토큰 정리 완료: 삭제된 토큰 수={}", deletedCount);
    }

    /**
     * 이메일로 사용자 조회 (컨트롤러용)
     */
    public User findUserByEmail(String email) {
        return userMapper.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));
    }

    /**
     * 사용자 ID로 조회 (컨트롤러용)
     */
    public User findUserById(Integer userId) {
        return userMapper.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));
    }

    /**
     * 리프레시 토큰에서 사용자 ID 추출
     */
    public Integer getUserIdFromRefreshToken(String refreshToken) {
        if (!jwtUtil.validateToken(refreshToken) || !jwtUtil.isRefreshToken(refreshToken)) {
            throw new IllegalArgumentException("유효하지 않은 리프레시 토큰입니다.");
        }
        return jwtUtil.getUserIdFromToken(refreshToken);
    }

    /**
     * 이메일 중복 체크
     */
    public boolean isEmailExists(String email) {
        return userMapper.existsByEmail(email);
    }

    /**
     * 닉네임 중복 체크
     */
    public boolean isNicknameExists(String nickname) {
        return userMapper.existsByNickname(nickname);
    }

    /**
     * 토큰 생성 및 저장
     */
    private Map<String, String> generateAndSaveTokens(User user) {
        // 액세스 토큰 생성
        String accessToken = jwtUtil.generateAccessToken(user.getUserId(), user.getEmail());

        // 리프레시 토큰 생성
        String refreshTokenValue = jwtUtil.generateRefreshToken(user.getUserId());
        LocalDateTime expiresAt = jwtUtil.getExpirationFromToken(refreshTokenValue);

        // 기존 리프레시 토큰 삭제 (단일 세션 정책)
        authMapper.deleteAllByUserId(user.getUserId());

        // 새 리프레시 토큰 저장
        RefreshToken refreshToken = RefreshToken.create(user.getUserId(), refreshTokenValue, expiresAt);
        authMapper.insertRefreshToken(refreshToken);

        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", accessToken);
        tokens.put("refreshToken", refreshTokenValue);

        return tokens;
    }

    /**
     * 소셜 사용자 생성
     */
    private User createSocialUser(String email, String nickname, String provider, String providerId) {
        // 닉네임 중복 확인 (중복시 숫자 추가)
        String uniqueNickname = generateUniqueNickname(nickname);

        // 소셜 사용자 생성
        User user = User.createSocialUser(email, uniqueNickname, provider, providerId);
        int insertedRows = userMapper.insertUser(user);

        if (insertedRows == 0) {
            throw new RuntimeException("소셜 회원가입에 실패했습니다.");
        }

        return user;
    }

    /**
     * 고유한 닉네임 생성 (중복 시 숫자 추가)
     */
    private String generateUniqueNickname(String baseNickname) {
        String nickname = baseNickname;
        int counter = 1;

        while (userMapper.existsByNickname(nickname)) {
            nickname = baseNickname + counter;
            counter++;
        }

        return nickname;
    }
}