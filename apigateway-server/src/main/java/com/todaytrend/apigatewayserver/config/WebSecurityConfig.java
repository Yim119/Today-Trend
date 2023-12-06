package com.todaytrend.apigatewayserver.config;

import com.todaytrend.apigatewayserver.config.jwt.TokenProvider1;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@RequiredArgsConstructor
@EnableWebFluxSecurity
public class WebSecurityConfig extends  SecurityConfigurerAdapter <DefaultSecurityFilterChain, HttpSecurity>{
    //    WebSecurityConfigurerAdapter
    private final TokenProvider1 tokenProvider;

        @Override
        public void configure(HttpSecurity http) throws Exception {
            http
                    .csrf(a -> a.disable())
//                        .csrf(csrf -> csrf.csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse()))
                    .httpBasic(b -> b.disable())
                    .cors(c -> c.configurationSource(corsConfigurationSource()))
                    .formLogin(httpSecurityFormLoginConfigurer -> httpSecurityFormLoginConfigurer.disable())
                    .httpBasic(httpSecurityHttpBasicConfigurer -> httpSecurityHttpBasicConfigurer.disable())
                    .logout(logoutConfigurer -> logoutConfigurer.disable())
                    .sessionManagement(sessionManagementConfigurer -> sessionManagementConfigurer
                            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    )
                    .addFilterBefore(tokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)

                    .authorizeRequests(authorizeRequests -> authorizeRequests
                            .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll() // OPTIONS 메서드를 허용
                            .requestMatchers("/api/auth/**").permitAll()
                            .requestMatchers("/api/**").permitAll()
                            .anyRequest().permitAll()
                    );
        }


    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.addAllowedOriginPattern("*");
        configuration.addAllowedHeader("*");
        configuration.addAllowedMethod("*");
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http
//                // 토큰 방식으로 인증을 하기 때문에 로그인 폼, 세션 비활성화
//                .csrf(httpSecurityCsrfSpec -> httpSecurityCsrfSpec.disable())
//                .formLogin(httpSecurityFormLoginConfigurer -> httpSecurityFormLoginConfigurer.disable())
//                .httpBasic(httpSecurityHttpBasicConfigurer -> httpSecurityHttpBasicConfigurer.disable())
//                .logout(logoutConfigurer -> logoutConfigurer.disable())
//                .sessionManagement(sessionManagementConfigurer -> sessionManagementConfigurer
//                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                )
//                // 헤더를 확인할 커스텀 필터
//                .addFilterBefore(tokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
//                // 토큰 재발급 URL은 인증 없이 접근 가능하도록 설정.
//                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
//                        .requestMatchers("/api/auth/**").permitAll()
//                        .requestMatchers("/api/**").permitAll()
//                        //.requestMatchers("/api/**").authenticated() // 나머지 API URL은 인증 필요
//                        .anyRequest().permitAll()
//                        //.anyRequest().authenticated() // 다른 요청은 인증 필요
//                );
//
//        return http.build();
//    }

    @Bean
    public TokenAuthenticationFilter tokenAuthenticationFilter() {
        return new TokenAuthenticationFilter(tokenProvider);
    }

}
