package com.seung.hyo.config.auth;

import com.seung.hyo.domain.user.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@RequiredArgsConstructor
@EnableWebSecurity // Spring Security 설정들을 활성화 시켜준다.
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CutomOAuth2UserService customOauth2UserService;


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .headers().frameOptions().disable().and()
                .authorizeRequests().antMatchers("/", "/css/", "/imges/**", "/js/**", "/h2-console/**").permitAll() // URL별 권한 관리를 설정하는 옵션의 시작점
                .antMatchers("/api/v1/**").hasRole(Role.USER.name()) // 권한 관리 대상 지정 URL, HTTP 메소드별로 관리 가능 permitAll()은 모든권한 "/api/v1/**" api는 USER권한만 접근가능
                .anyRequest().authenticated() // 설정 값들 이외 나머지 URL들 authenticated()는 모두 인증된 사용자 들에게만 허용 (로그인된)
                .and()
                .logout() // 로그아웃 기능
                .logoutSuccessUrl("/") // 로그아웃 성공 시 "/" 주소로 이동
                .and()
                .oauth2Login() // OAuth2 로그인 기능에 대한 여러 설정의 진입점
                .userInfoEndpoint() // OAuth2 로그인 성공 이후 사용자 정보를 가져올 때의 설정
                .userService(customOauth2UserService); // 소셜 로그인 성공 시 후속 조치를 진행할 UserService 인터페이스의 구현체를 등록
    }
}
