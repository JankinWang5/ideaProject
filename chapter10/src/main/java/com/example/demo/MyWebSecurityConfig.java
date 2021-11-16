package com.example.demo;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.security.sasl.AuthenticationException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

@Configuration
public class MyWebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Bean
    PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        auth.inMemoryAuthentication()
                .withUser("root").password("123").roles("ADMIN","DBA")
                .and()
                .withUser("admin").password("123").roles("ADMIN","USER")
                .and()
                .withUser("sang").password("123").roles("USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception{
        //调用authorizeRequests()方法开启HttpSecurity的配置
        http.authorizeRequests()
                //用户访问“/admin/**”模式的URL必须具备ADMIN的角色
                .antMatchers("/admin/**")
                .hasRole("ADMIN")
                //用户访问“/user/**”模式的URL必须具备ADMIN或USER的角色
                .antMatchers("/user/**")
                .access("hasAnyRole('ADMIN','USER')")
                //用户访问“/db/**”模式的URL必须具备ADMIN和DBA的角色
                .antMatchers("/db/**")
                .access("hasRole('ADMIN') and hasRole('DBA')")
                //除了前面定义的URL模式之外，用户访问其他的URL都必须认证后访问（登录后访问）
                .anyRequest()
                .authenticated()
                //开启表单登录，即读者一开始看到的登录页面，
                // 同时配置了登录接口为“/login”，
                // 即可以直接调用“/login”接口，
                // 发起一个POST请求进行登录，
                // 登录参数中用户名必须命名为username，
                // 密码必须命名为password，
                // 配置loginProcessingUrl接口主要是方便Ajax或者移动端调用登录接口。

                // 最后还配置了permitAll，表示和登录相关的接口都不需要认证即可访问。
                .and()
                .formLogin()
                .loginProcessingUrl("/login")
                .permitAll()
                .and()
                //关闭csrf
                .csrf()
                .disable();

    }
}
