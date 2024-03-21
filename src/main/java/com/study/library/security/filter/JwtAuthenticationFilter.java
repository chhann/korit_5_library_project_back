package com.study.library.security.filter;

import com.study.library.config.SecurityConfig;
import com.study.library.jwt.JwtProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends GenericFilter {

    @Autowired
    private JwtProvider jwtProvider;

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        Boolean isPermitAll = (boolean) request.getAttribute("isPermitAll");

        if(!isPermitAll) {
            String accessToken = request.getHeader("Authorization");
            String removedBearerToken = jwtProvider.removeBearer(accessToken); // bear 가 없는 클린한 토큰값
            Claims claims = null;

            try{
                claims = jwtProvider.getClaims(removedBearerToken); // 유효성 검사: 토큰이 위조되었는지 기간이 다되었는지
            } catch (Exception e) {
                response.sendError(HttpStatus.UNAUTHORIZED.value()); // 인증실패 HttpStatus.UNAUTHORIZED.value() or 401
                return;
            }

            // 토큰은 유효한데 DB에 자료가 없을경우
            Authentication authentication = jwtProvider.getAuthentication(claims);

            if(authentication == null) {
                response.sendError(HttpStatus.UNAUTHORIZED.value()); // 인증실패 HttpStatus.UNAUTHORIZED.value() or 401
                return;
            }

            SecurityContextHolder.getContext().setAuthentication(authentication);


        }



        // 전처리
        filterChain.doFilter(request, response);
        // 후처리


    }



}
