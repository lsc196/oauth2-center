package com.example.oauthcenter.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.*;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter{

    @Autowired
    MyUserDetailService myUserDetailService;

//    @Bean
//    public  PasswordEncoder createDelegatingPasswordEncoder() {
//        //使用了这个Bean返回 PasswordEncoder，会替换默认的 PasswordEncoderFactories.createDelegatingPasswordEncoder() ，密码存储格式 也是按如下
//        String encodingId = "bcrypttest";
//        Map<String, PasswordEncoder> encoders = new HashMap();
//        encoders.put(encodingId, new BCryptPasswordEncoder());
//        encoders.put("noop", NoOpPasswordEncoder.getInstance());
//        return new DelegatingPasswordEncoder(encodingId, encoders);
//    }

//    @Bean
//    public  static PasswordEncoder passwordEncoder( ){
//        //如果之前的密码不是{id}password 格式，而是明文密码，可设置 DelegatingPasswordEncoder 默认密码存储格式为 NoOpPasswordEncoder。。它原本默认的是 bcrypt
//        DelegatingPasswordEncoder delegatingPasswordEncoder =
//                (DelegatingPasswordEncoder) PasswordEncoderFactories.createDelegatingPasswordEncoder();
//        //设置defaultPasswordEncoderForMatches为NoOpPasswordEncoder
//        delegatingPasswordEncoder.setDefaultPasswordEncoderForMatches(NoOpPasswordEncoder.getInstance());
//        return  delegatingPasswordEncoder;
//    }


    @Autowired
    public void globalUserDetails(AuthenticationManagerBuilder auth) throws Exception {
        //用户信息保存在内存中
        //在inMemoryAuthentication()后面多了".passwordEncoder(new BCryptPasswordEncoder())",相当于登陆时用BCrypt加密方式对用户密码进行处理。
        //在鉴定角色roler时，会默认加上ROLLER_前缀
//        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder()).withUser("user")
//                .password(new BCryptPasswordEncoder().encode("user")).roles("USER");
        //SpringSecurity5 使用  PasswordEncoderFactories.createDelegatingPasswordEncoder(); 为默认密码解析
//        auth.inMemoryAuthentication().withUser("user")
//                .password("{bcrypttest}$2a$10$szxj4uW7MhxVlgLsCyE/KuH8WEIk8Dr67u9iIPTW9MTwc90V7UMhu").roles("USER").and()
//                .withUser("test").password("12345").roles("TEST");
        //使用数据库保存账密
        //注入userDetailsService的实现类,并设置密码存储格式为 明文 格式
        auth.userDetailsService(myUserDetailService).passwordEncoder(NoOpPasswordEncoder.getInstance());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin() //登记界面，默认是permit All
                .and()
                .authorizeRequests().antMatchers("/auth/**","/","/home").permitAll() //不用身份认证可以访问
                .and()
                .authorizeRequests().anyRequest().authenticated() //其它的请求要求必须有身份认证
                .and()
                .csrf() //防止CSRF（跨站请求伪造）配置
                .requireCsrfProtectionMatcher(new AntPathRequestMatcher("/oauth/authorize")).disable();
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    public static void main(String[] args) {
        String pd = "123456";
        System.out.println(new BCryptPasswordEncoder().encode(pd));
        System.out.println(NoOpPasswordEncoder.getInstance().encode(pd));
        PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        System.out.println(passwordEncoder.encode(pd));
    }
}