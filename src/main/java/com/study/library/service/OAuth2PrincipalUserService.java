package com.study.library.service;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Map;

@Service
public class OAuth2PrincipalUserService implements OAuth2UserService {

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = oAuth2UserService.loadUser(userRequest);
        Map<String, Object> attributes = oAuth2User.getAttributes();

        System.out.println(attributes);

        String provider = userRequest.getClientRegistration().getClientName(); // Google, Kakao, Naver
        Map<String, Object> newAttributes = null;
        String id = null;
        switch (provider) {
            case "Google" :
                id = attributes.get("sub").toString();
                break;
            case "Naver" :
                Map<String, Object> response = (Map<String, Object>) attributes.get("response");
                id = response.get("id").toString();
                break;
            case "Kakao" :
                id = attributes.get("id").toString();
                break;
        }
        newAttributes = Map.of("id", id, "provider", provider);

        // DefaultOAuth2User -> 정상적이게 성생이되면 successhandler 로 보냄
        return new DefaultOAuth2User(oAuth2User.getAuthorities(), newAttributes, "id");
    }

}
