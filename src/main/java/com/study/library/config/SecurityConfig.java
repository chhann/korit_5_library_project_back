package com.study.library.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity // override 로 제정의한것을 따라가라
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // csrf() 토큰 이것만 쓰면 서버사이드 렌더링만 가능함
        // antMatchers
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/auth/**", "/server/**")
                .permitAll() // 이 위에 요청들은 다 인증 필요없음 (허용 해줘라)
                .anyRequest()
                .authenticated();
    }




}
