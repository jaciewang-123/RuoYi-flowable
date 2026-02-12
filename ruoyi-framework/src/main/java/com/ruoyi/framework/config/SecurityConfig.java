package com.ruoyi.framework.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.CorsFilter;
import com.ruoyi.framework.config.properties.PermitAllUrlProperties;
import com.ruoyi.framework.security.filter.JwtAuthenticationTokenFilter;
import com.ruoyi.framework.security.handle.AuthenticationEntryPointImpl;
import com.ruoyi.framework.security.handle.LogoutSuccessHandlerImpl;

/**
 * spring security配置（适配Spring Boot 3.1.5 + Java 17）
 *
 * @author ruoyi
 */
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)
@Configuration
public class SecurityConfig
{
    /**
     * 自定义用户认证逻辑
     */
    @Autowired
    private UserDetailsService userDetailsService;

    /**
     * 认证失败处理类
     */
    @Autowired
    private AuthenticationEntryPointImpl unauthorizedHandler;

    /**
     * 退出处理类
     */
    @Autowired
    private LogoutSuccessHandlerImpl logoutSuccessHandler;

    /**
     * token认证过滤器
     */
    @Autowired
    private JwtAuthenticationTokenFilter authenticationTokenFilter;

    /**
     * 跨域过滤器
     */
    @Autowired
    private CorsFilter corsFilter;

    /**
     * 允许匿名访问的地址
     */
    @Autowired
    private PermitAllUrlProperties permitAllUrl;

    /**
     * 身份验证实现（适配Java 17模块化）
     */
    @Bean
    public AuthenticationManager authenticationManager()
    {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        daoAuthenticationProvider.setPasswordEncoder(bCryptPasswordEncoder());
        // 关闭隐藏用户未找到异常，避免Java 17反射拦截
        daoAuthenticationProvider.setHideUserNotFoundExceptions(false);
        return new ProviderManager(daoAuthenticationProvider);
    }

    /**
     * 核心安全过滤链配置（修复requestMatchers类型错误）
     */
    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception
    {
        return httpSecurity
            // CSRF禁用，因为不使用session
            .csrf(csrf -> csrf.disable())
            // 禁用HTTP响应标头的缓存和X-Frame-Options限制
            .headers(headers -> {
                headers.cacheControl(cache -> cache.disable())
                    .frameOptions(frame -> frame.sameOrigin());
            })
            // 认证失败处理类
            .exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler))
            // 基于token，所以不需要session
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            // 配置权限规则（核心修复：所有路径统一使用AntPathRequestMatcher）
            .authorizeHttpRequests(requests -> {
                // ========== 修复点1：批量处理permitAllUrl，转为数组一次性传入 ==========
                AntPathRequestMatcher[] permitAllMatchers = permitAllUrl.getUrls().stream()
                    .map(url -> new AntPathRequestMatcher(url))
                    .toArray(AntPathRequestMatcher[]::new);
                requests.requestMatchers(permitAllMatchers).permitAll();

                // ========== 修复点2：所有固定路径都显式使用AntPathRequestMatcher ==========
                // 基础匿名路径：登录、注册、验证码
                requests.requestMatchers(
                    new AntPathRequestMatcher("/login"),
                    new AntPathRequestMatcher("/register"),
                    new AntPathRequestMatcher("/captchaImage")
                ).permitAll();

                // 静态资源匿名访问（GET方法）
                requests.requestMatchers(
                    new AntPathRequestMatcher("/"),
                    new AntPathRequestMatcher("/*.html"),
                    new AntPathRequestMatcher("/**/*.html"),
                    new AntPathRequestMatcher("/**/*.css"),
                    new AntPathRequestMatcher("/**/*.js"),
                    new AntPathRequestMatcher("/profile/**")
                ).permitAll();

                // Swagger/SpringDoc文档 + Druid监控 匿名访问
                requests.requestMatchers(
                    new AntPathRequestMatcher("/swagger-ui.html"),
                    new AntPathRequestMatcher("/swagger-resources/**"),
                    new AntPathRequestMatcher("/webjars/**"),
                    new AntPathRequestMatcher("/*/api-docs"),
                    new AntPathRequestMatcher("/swagger-ui/**"),
                    new AntPathRequestMatcher("/v3/api-docs/**"),
                    new AntPathRequestMatcher("/doc.html"),
                    new AntPathRequestMatcher("/druid/**")
                ).permitAll();

                // 除上面外的所有请求全部需要鉴权认证
                requests.anyRequest().authenticated();
            })
            // 登出配置（显式指定AntPathRequestMatcher）
            .logout(logout -> logout
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessHandler(logoutSuccessHandler))
            // 过滤器顺序：CORS过滤器在前，然后是JWT过滤器
            .addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(authenticationTokenFilter, UsernamePasswordAuthenticationFilter.class)
            .build();
    }

    /**
     * 强散列哈希加密实现
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder()
    {
        return new BCryptPasswordEncoder();
    }
}