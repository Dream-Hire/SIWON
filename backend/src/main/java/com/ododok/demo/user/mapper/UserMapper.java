package com.ododok.demo.user.mapper;

import com.ododok.demo.user.entity.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.Optional;

/**
 * 사용자 정보 관련 MyBatis 매퍼
 */
@Mapper
public interface UserMapper {

    /**
     * 사용자 생성 (일반 회원가입 / 소셜 로그인)
     * @param user 사용자 정보
     * @return 생성된 행 수
     */
    int insertUser(User user);

    /**
     * 사용자 ID로 조회
     * @param userId 사용자 ID
     * @return 사용자 정보
     */
    Optional<User> findById(@Param("userId") Integer userId);

    /**
     * 이메일로 사용자 조회 (로그인 시 사용)
     * @param email 이메일
     * @return 사용자 정보
     */
    Optional<User> findByEmail(@Param("email") String email);

    /**
     * 소셜 로그인 사용자 조회 (provider + providerId로 조회)
     * @param provider 소셜 로그인 제공자 (NAVER 등)
     * @param providerId 제공자에서 제공한 사용자 ID
     * @return 사용자 정보
     */
    Optional<User> findByProviderAndProviderId(
            @Param("provider") String provider,
            @Param("providerId") String providerId
    );

    /**
     * 이메일 중복 체크 (회원가입 시 사용)
     * @param email 이메일
     * @return 존재하면 true
     */
    boolean existsByEmail(@Param("email") String email);

    /**
     * 닉네임 중복 체크
     * @param nickname 닉네임
     * @return 존재하면 true
     */
    boolean existsByNickname(@Param("nickname") String nickname);

    /**
     * 사용자 정보 수정 (프로필 등)
     * @param user 수정할 사용자 정보
     * @return 수정된 행 수
     */
    int updateUser(User user);

    /**
     * 비밀번호 변경
     * @param userId 사용자 ID
     * @param newPassword 새 비밀번호 (암호화된)
     * @return 수정된 행 수
     */
    int updatePassword(@Param("userId") Integer userId, @Param("password") String newPassword);

    /**
     * 프로필 이미지 URL 업데이트
     * @param userId 사용자 ID
     * @param profileUrl 프로필 이미지 URL
     * @return 수정된 행 수
     */
    int updateProfileUrl(@Param("userId") Integer userId, @Param("profileUrl") String profileUrl);

    /**
     * 사용자 삭제 (회원 탈퇴)
     * @param userId 사용자 ID
     * @return 삭제된 행 수
     */
    int deleteUser(@Param("userId") Integer userId);

    /**
     * 소셜 계정 연동 (기존 일반 계정에 소셜 정보 추가)
     * @param userId 사용자 ID
     * @param provider 소셜 로그인 제공자
     * @param providerId 제공자에서 제공한 사용자 ID
     * @return 수정된 행 수
     */
    int linkSocialAccount(
            @Param("userId") Integer userId,
            @Param("provider") String provider,
            @Param("providerId") String providerId
    );
}