package com.ododok.demo.auth.controller;

import com.ododok.demo.auth.dto.LoginRequest;
import com.ododok.demo.auth.dto.SignupRequest;
import com.ododok.demo.auth.dto.TokenResponse;
import com.ododok.demo.auth.service.AuthService;
import com.ododok.demo.user.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import java.util.HashMap;
import java.util.Map;

/**
 * 인증 관련 REST API 컨트롤러
 */
@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Validated
public class AuthController {

    private final AuthService authService;

    /**
     * 회원가입
     * POST /api/auth/signup
     */
    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody SignupRequest request) {
        try {
            // 비밀번호 확인 검증
            if (!request.isPasswordMatched()) {
                return ResponseEntity.badRequest()
                        .body(createErrorResponse("비밀번호가 일치하지 않습니다."));
            }

            // 회원가입 처리
            User user = authService.signUp(
                    request.getEmail(),
                    request.getPassword(),
                    request.getNickname()
            );

            log.info("회원가입 성공: userId={}, email={}", user.getUserId(), user.getEmail());

            return ResponseEntity.ok()
                    .body(createSuccessResponse("회원가입이 완료되었습니다."));

        } catch (IllegalArgumentException e) {
            log.warn("회원가입 실패: {}", e.getMessage());
            return ResponseEntity.badRequest()
                    .body(createErrorResponse(e.getMessage()));
        } catch (Exception e) {
            log.error("회원가입 중 오류 발생", e);
            return ResponseEntity.internalServerError()
                    .body(createErrorResponse("회원가입 중 오류가 발생했습니다."));
        }
    }

    /**
     * 로그인
     * POST /api/auth/login
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        try {
            // 로그인 처리
            Map<String, String> tokens = authService.signIn(
                    request.getEmail(),
                    request.getPassword()
            );

            // 사용자 정보 조회
            User user = authService.findUserByEmail(request.getEmail());

            // 토큰 응답 생성
            TokenResponse response = TokenResponse.of(
                    tokens.get("accessToken"),
                    tokens.get("refreshToken"),
                    user
            );

            log.info("로그인 성공: userId={}, email={}", user.getUserId(), user.getEmail());

            return ResponseEntity.ok(response);

        } catch (IllegalArgumentException e) {
            log.warn("로그인 실패: {}", e.getMessage());
            return ResponseEntity.badRequest()
                    .body(createErrorResponse(e.getMessage()));
        } catch (Exception e) {
            log.error("로그인 중 오류 발생", e);
            return ResponseEntity.internalServerError()
                    .body(createErrorResponse("로그인 중 오류가 발생했습니다."));
        }
    }

    /**
     * 토큰 갱신
     * POST /api/auth/refresh
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody Map<String, String> request) {
        try {
            String refreshToken = request.get("refreshToken");

            if (refreshToken == null || refreshToken.trim().isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(createErrorResponse("리프레시 토큰이 필요합니다."));
            }

            // 토큰 갱신
            Map<String, String> tokens = authService.refreshTokens(refreshToken);

            // 사용자 정보 조회 (토큰에서 사용자 ID 추출)
            Integer userId = authService.getUserIdFromRefreshToken(refreshToken);
            User user = authService.findUserById(userId);

            // 토큰 응답 생성
            TokenResponse response = TokenResponse.of(
                    tokens.get("accessToken"),
                    tokens.get("refreshToken"),
                    user
            );

            log.info("토큰 갱신 성공: userId={}", userId);

            return ResponseEntity.ok(response);

        } catch (IllegalArgumentException e) {
            log.warn("토큰 갱신 실패: {}", e.getMessage());
            return ResponseEntity.badRequest()
                    .body(createErrorResponse(e.getMessage()));
        } catch (Exception e) {
            log.error("토큰 갱신 중 오류 발생", e);
            return ResponseEntity.internalServerError()
                    .body(createErrorResponse("토큰 갱신 중 오류가 발생했습니다."));
        }
    }

    /**
     * 로그아웃
     * POST /api/auth/logout
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody Map<String, String> request) {
        try {
            String refreshToken = request.get("refreshToken");

            if (refreshToken != null && !refreshToken.trim().isEmpty()) {
                authService.signOut(refreshToken);
            }

            log.info("로그아웃 성공");

            return ResponseEntity.ok()
                    .body(createSuccessResponse("로그아웃되었습니다."));

        } catch (Exception e) {
            log.error("로그아웃 중 오류 발생", e);
            return ResponseEntity.internalServerError()
                    .body(createErrorResponse("로그아웃 중 오류가 발생했습니다."));
        }
    }

    /**
     * 이메일 중복 체크
     * GET /api/auth/check-email?email=test@example.com
     */
    @GetMapping("/check-email")
    public ResponseEntity<?> checkEmail(@RequestParam String email) {
        try {
            boolean exists = authService.isEmailExists(email);

            Map<String, Object> response = new HashMap<>();
            response.put("available", !exists);
            response.put("message", exists ? "이미 사용 중인 이메일입니다." : "사용 가능한 이메일입니다.");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("이메일 중복 체크 중 오류 발생", e);
            return ResponseEntity.internalServerError()
                    .body(createErrorResponse("이메일 중복 체크 중 오류가 발생했습니다."));
        }
    }

    /**
     * 닉네임 중복 체크
     * GET /api/auth/check-nickname?nickname=테스트
     */
    @GetMapping("/check-nickname")
    public ResponseEntity<?> checkNickname(@RequestParam String nickname) {
        try {
            boolean exists = authService.isNicknameExists(nickname);

            Map<String, Object> response = new HashMap<>();
            response.put("available", !exists);
            response.put("message", exists ? "이미 사용 중인 닉네임입니다." : "사용 가능한 닉네임입니다.");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("닉네임 중복 체크 중 오류 발생", e);
            return ResponseEntity.internalServerError()
                    .body(createErrorResponse("닉네임 중복 체크 중 오류가 발생했습니다."));
        }
    }

    /**
     * 성공 응답 생성
     */
    private Map<String, Object> createSuccessResponse(String message) {
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", message);
        return response;
    }

    /**
     * 에러 응답 생성
     */
    private Map<String, Object> createErrorResponse(String message) {
        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("error", message);
        return response;
    }
}