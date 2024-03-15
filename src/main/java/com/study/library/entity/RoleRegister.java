package com.study.library.entity;

import lombok.Data;

import java.time.LocalDateTime;

@Data
public class RoleRegister {
    private int roleRegisterId;
    private int userId;
    private int roleId;
    private LocalDateTime createDate;
    private LocalDateTime updateDate;
    private Role role;
}
