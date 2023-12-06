package com.todaytrend.userservice.dto;

import com.todaytrend.userservice.domain.enum_.Gender;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import lombok.Builder;
import lombok.Getter;


@Getter @Builder
public class ResponseUserDto {
    private String phone;

    @Enumerated(EnumType.STRING)
    private Gender gender;

    private String birth;

    private String name;

    private String nickname;

    private String website;

    private String introduction;

    private String profileImage;
}
