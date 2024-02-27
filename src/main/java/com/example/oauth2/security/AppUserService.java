package com.example.oauth2.security;

import jakarta.annotation.PostConstruct;
import lombok.Value;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@Value
public class AppUserService implements UserDetailsService {
    PasswordEncoder passwordEncoder;
    Map<String,AppUser>  users = new HashMap<>();

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return users.get(username);
    }
    @PostConstruct
    private void createHardcodedUsers(){
        var b1 =  AppUser.builder().username("b1").password(passwordEncoder.encode("1234")).authorities(List.of(new SimpleGrantedAuthority("READ"))).build();
        var b2 =  AppUser.builder().username("b2").password(passwordEncoder.encode("1234")).authorities(Collections.emptyList()).build();

        createUser(b1);
        createUser(b2);
    }

    private void createUser(AppUser user) {
        users.putIfAbsent(user.getUsername(),user);
    }

    // FOR GOOGLE
     OAuth2UserService<OidcUserRequest, OidcUser> oidcLoginHandler() {
        return userRequest -> {
            LoginProvider provider = getProvider(userRequest.getClientRegistration());
            OidcUserService delegate = new OidcUserService();
            OidcUser oidcUser = delegate.loadUser(userRequest);
            return  AppUser
                    .builder()
                    .username(oidcUser.getEmail())
                    .name(oidcUser.getFullName())
                    .email(oidcUser.getEmail())
                    .attributes(oidcUser.getAttributes())
                    .authorities(oidcUser.getAuthorities())
                    .password(passwordEncoder.encode(UUID.randomUUID().toString()))
                    .userId(oidcUser.getName())
                    .imageUrl(oidcUser.getAttribute("picture"))
                    .provider(provider)
                    .build();

        };
    }

    private LoginProvider getProvider(ClientRegistration userRequest) {
        LoginProvider provider = LoginProvider.valueOf(userRequest.getRegistrationId().toUpperCase());
        return provider;
    }

    // FOR GITHUB
     OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2LoginHandler() {
        return userRequest -> {
            LoginProvider provider = getProvider(userRequest.getClientRegistration());
            DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
            OAuth2User oAuth2User = delegate.loadUser(userRequest);
            return AppUser
                    .builder()
                    .username(oAuth2User.getAttribute("login"))
                    .name(oAuth2User.getAttribute("login"))
                    .imageUrl(oAuth2User.getAttribute("avatar-url"))
                    .provider(provider)
                    .password(passwordEncoder.encode(UUID.randomUUID().toString()))
                    .userId(oAuth2User.getName())
                    .authorities(oAuth2User.getAuthorities())
                    .attributes(oAuth2User.getAttributes())
                    .build();
        };
    }

}
