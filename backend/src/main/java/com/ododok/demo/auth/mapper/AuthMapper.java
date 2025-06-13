package com.ododok.demo.auth.mapper;

import com.ododok.demo.auth.entity.RefreshToken;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * 인증 관련 MyBatis 매퍼 (RefreshToken 관리)
 */
@Mapper
public interface AuthMapper {

    /**
     * 리프레시 토큰 저장
     * @param refreshToken 리프레시 토큰 정보
     * @return 생성된 행 수
     */
    int insertRefreshToken(RefreshToken refreshToken);

    /**
     * 토큰 값으로 리프레시 토큰 조회
     * @param token 토큰 값
     * @return 리프레시 토큰 정보
     */
    Optional<RefreshToken> findByToken(@Param("token") String token);

    /**
     * 사용자 ID로 리프레시 토큰 조회 (가장 최근 것)
     * @param userId 사용자 ID
     * @return 리프레시 토큰 정보
     */
    Optional<RefreshToken> findByUserId(@Param("userId") Integer userId);

    /**
     * 사용자의 모든 리프레시 토큰 조회
     * @param userId 사용자 ID
     * @return 리프레시 토큰 목록
     */
    List<RefreshToken> findAllByUserId(@Param("userId") Integer userId);

    /**
     * 토큰 값으로 리프레시 토큰 삭제 (로그아웃)
     * @param token 토큰 값
     * @return 삭제된 행 수
     */
    int deleteByToken(@Param("token") String token);

    /**
     * 사용자의 모든 리프레시 토큰 삭제 (전체 로그아웃)
     * @param userId 사용자 ID
     * @return 삭제된 행 수
     */
    int deleteAllByUserId(@Param("userId") Integer userId);

    /**
     * 만료된 리프레시 토큰 삭제 (정리 작업)
     * @param now 현재 시간
     * @return 삭제된 행 수
     */
    int deleteExpiredTokens(@Param("now") LocalDateTime now);

    /**
     * 토큰이 존재하는지 확인
     * @param token 토큰 값
     * @return 존재하면 true
     */
    boolean existsByToken(@Param("token") String token);

    /**
     * 사용자의 리프레시 토큰 개수 조회
     * @param userId 사용자 ID
     * @return 토큰 개수
     */
    int countByUserId(@Param("userId") Integer userId);

    /**
     * 기존 토큰을 새 토큰으로 업데이트 (토큰 로테이션)
     * @param oldToken 기존 토큰
     * @param newToken 새 토큰
     * @param newExpiresAt 새 만료시간
     * @return 수정된 행 수
     */
    int updateToken(
            @Param("oldToken") String oldToken,
            @Param("newToken") String newToken,
            @Param("newExpiresAt") LocalDateTime newExpiresAt
    );
}