package com.example.demo;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

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
                //配置了loginPage，即登录页面，
                // 配置了loginPage后，
                // 如果用户未获授权就访问一个需要授权才能访问的接口，
                // 就会自动跳转到login_page页面让用户登录，
                // 这个login_page就是开发者自定义的登录页面，
                // 而不再是Spring Security提供的默认登录页。
                .loginPage("/login_page")
                //登录请求处理接口，无论是自定义登录页面还是移动端登录，都需要使用该接口。
                .loginProcessingUrl("/login")
                //定义了认证所需的用户名和密码的参数名，
                //默认用户名参数是username，密码参数是password，可以在这里自定义。
                .usernameParameter("name")
                .passwordParameter("passwd")
                //定义了登录成功的处理逻辑。
                // 用户登录成功后可以跳转到某一个页面，也可以返回一段JSON，这个要看具体业务逻辑，
                // 本案例假设是第二种，用户登录成功后，返回一段登录成功的JSON。
                // onAuthenticationSuccess方法的第三个参数一般用来获取当前登录用户的信息，
                // 在登录成功后，可以获取当前登录用户的信息一起返回给客户端。
                .successHandler(new AuthenticationSuccessHandler(){
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest req,
                                                        HttpServletResponse resp,
                                                        Authentication auth)
                            throws IOException{
                        Object principal = auth.getPrincipal();
                        resp.setContentType("application/json;charset=utf-8");
                        PrintWriter out = resp.getWriter();
                        resp.setStatus(200);
                        Map<String,Object> map = new HashMap<>();
                        map.put("status",200);
                        map.put("msg",principal);
                        ObjectMapper om = new ObjectMapper();
                        out.write(om.writeValueAsString(map));
                        out.flush();
                        out.close();
                    }
                })
                //定义了登录失败的处理逻辑，和登录成功类似，
                // 不同的是，登录失败的回调方法里有一个AuthenticationException参数，
                // 通过这个异常参数可以获取登录失败的原因，进而给用户一个明确的提示
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest req,
                                                        HttpServletResponse resp,
                                                        org.springframework.security.core.AuthenticationException e)
                            throws IOException{
                        resp.setContentType("application/json;charset=utf-8");
                        PrintWriter out = resp.getWriter();
                        resp.setStatus(401);
                        Map<String,Object> map = new HashMap<>();
                        map.put("status",401);
                        if(e instanceof LockedException){
                            map.put("msg","账户被锁定，登录失败");
                        }else if (e instanceof BadCredentialsException) {
                            map.put("msg", "账户名或密码输入错误，登录失败!");
                        } else if (e instanceof DisabledException) {
                            map.put("msg", "账户被禁用，登录失败!");
                        } else if (e instanceof AccountExpiredException) {
                            map.put("msg", "账户已过期，登录失败!");
                        } else if (e instanceof CredentialsExpiredException) {
                            map.put("msg", "密码已过期，登录失败!");
                        } else {
                            map.put("msg", "登录失败!");
                        }
                        ObjectMapper om = new ObjectMapper();
                        out.write(om.writeValueAsString(map));
                        out.flush();
                        out.close();
                    }
                })
                .permitAll()
                .and()
                //开启注销登录的配置
                .logout()
                //配置注销登录请求URL为“/logout”，默认也是“/logout”。
                .logoutUrl("/logout")
                //是否清除身份认证信息，默认为true，表示清除。
                .clearAuthentication(true)
                //是否使Session失效，默认为true。
                .invalidateHttpSession(true)
                //配置一个LogoutHandler，
                // 开发者可以在LogoutHandler中完成一些数据清除工作，例如Cookie的清除。
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest req,
                                       HttpServletResponse resp,
                                       Authentication auth) {
                    }
                })
                //配置一个LogoutSuccessHandler，
                // 开发者可以在这里处理注销成功后的业务逻辑，
                // 例如返回一段JSON提示或者跳转到登录页面等
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest req,
                                                HttpServletResponse resp,
                                                Authentication auth)
                            throws IOException {
                        resp.sendRedirect("/login_page");
                    }
                })
                .and()
                //关闭csrf
                .csrf()
                .disable();

    }
}
