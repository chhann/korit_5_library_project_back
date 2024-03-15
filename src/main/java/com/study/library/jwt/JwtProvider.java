package com.study.library.jwt;

import com.study.library.entity.User;
import com.study.library.security.PrincipalUser;
import io.jsonwebtoken.Jwts;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;


import java.security.Key;
import java.util.Collection;
import java.util.Date;

//토큰 설정
@Component
public class JwtProvider {

    private final Key key;

    // 토큰 암호화
    public JwtProvider(@Value("${jwt.secret}") String secret){
        key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
    }


    public String generateToken(User user) {

        int userid = user.getUserId();
        String username = user.getUsername();
        Collection<? extends GrantedAuthority> authorities = user.getAuthorities();
        Date expireDate = new Date(new Date().getTime() + (1000 * 60 * 60 * 24)); // 1초 * 1분 * 1시간 * 24시간

        String accessToken = Jwts.builder() // json 형식 파일로 들어감
                .claim("userId", userid)
                .claim("username", username)
                .claim("authorities", authorities)
                .setExpiration(expireDate)
                .signWith(key, SignatureAlgorithm.HS256) // 암호화 key, 알고리즘
                .compact();

        return accessToken;
    }
}
