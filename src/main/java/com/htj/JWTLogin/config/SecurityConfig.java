package com.htj.JWTLogin.config;

import com.htj.JWTLogin.jwt.JWTFilter;
import com.htj.JWTLogin.jwt.JWTUtil;
import com.htj.JWTLogin.jwt.LoginFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    //AuthenticationManager가 인자로 받을 AuthenticationConfiguraion 객체 생성자 주입
    private final AuthenticationConfiguration authenticationConfiguration;
    //JWTUtil 주입
    private final JWTUtil jwtUtil;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JWTUtil jwtUtil) {

        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtUtil = jwtUtil;
    }

    //AuthenticationManager Bean 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {

        return configuration.getAuthenticationManager();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        //csrf disable
        http
                .csrf((auth) -> auth.disable());

        //Form 로그인 방식 disable => form 로그인 방식은 사용하지 않겠다.
        http
                .formLogin((auth) -> auth.disable());

        //http basic 인증 방식 disable => http basic 인증 방식은 사용하지 않겠다.
        http
                .httpBasic((auth) -> auth.disable());

        //경로별 인가 작업
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/join").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated());
        /*
            로그인,main,회원가입에서는 모두 허용
            admin페이지는 "ADMIN"이란 권한을 가진 사용자만 접근 가능
            그 외 나머지는 authenticated(인증된) 사용자 접근 가능
         */


        //JWTFilter 등록
        http
                .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);

        //필터 추가 LoginFilter()는 인자를 받음 (AuthenticationManager() 메소드에 authenticationConfiguration 객체를 넣어야 함) 따라서 등록 필요
        //AuthenticationManager()와 JWTUtil 인수 전달
        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class);

        /*
        .addFilterAt(Filter filter, Class<? extends Filter> atFilter) => 원하는 자리에
        .addFilterBefore(Filter filter, Class<? extends Filter> beforeFilter) => 해당하는 필터 전에
        .addFilterAfter(Filter filter, Class<? extends Filter> afterFilter) => 해당하는 필터 이후에
              등록할 필터 ------------   ----------------------------------- before/at/after 위치
         */
        //세션 설정
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        // JWT 방식에서는 session을 항상 STATELESS항 상태로 관리한다.

        return http.build();
    }
}
