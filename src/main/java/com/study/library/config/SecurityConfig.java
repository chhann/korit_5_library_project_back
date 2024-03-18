package com.study.library.config;

import com.study.library.security.exception.AuthEntryPoint;
import com.study.library.security.filter.JwtAuthenticationFilter;
import com.study.library.security.filter.PermitAllFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;

@EnableWebSecurity // override 로 제정의한것을 따라가라
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private PermitAllFilter permitAllFilter;
    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;
    @Autowired
    private AuthEntryPoint authEntryPoint;

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors(); // 크로스오리진 필터가 먼저 돌아간다 (WebMvcConfig)
        // csrf() 토큰 이것만 쓰면 서버사이드 렌더링만 가능함
        // antMatchers
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/auth/**", "/server/**")
                .permitAll() // 이 위에 요청들은 다 인증 필요없음 (허용 해줘라)
                .anyRequest()
                .authenticated() // 오류가 나면 여기서 응답이 일어난다
                .and()
                .addFilterAfter(permitAllFilter, LogoutFilter.class)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling()                           // 에러 발생했을때 출력되게 하기
                .authenticationEntryPoint(authEntryPoint);     // 에러 발생했을때 출력되게 하기 매개변수에 엔트리 포인트 넣기
    }




}
