package com.ododok.demo.auth.dto;

import lombok.*;
import jakarta.validation.constraints.*;

/**
 * 비밀번호 변경 요청 DTO
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
class ChangePasswordRequest {

    @NotBlank(message = "현재 비밀번호는 필수입니다.")
    private String currentPassword;

    @NotBlank(message = "새 비밀번호는 필수입니다.")
    @Size(min = 8, max = 100, message = "비밀번호는 8자 이상 100자 이하여야 합니다.")
    @Pattern(
            regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&].*$",
            message = "비밀번호는 대소문자, 숫자, 특수문자를 각각 하나 이상 포함해야 합니다."
    )
    private String newPassword;

    @NotBlank(message = "새 비밀번호 확인은 필수입니다.")
    private String confirmNewPassword;

    /**
     * 새 비밀번호 확인 검증
     */
    public boolean isNewPasswordMatched() {
        return newPassword != null && newPassword.equals(confirmNewPassword);
    }
}
