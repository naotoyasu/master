package com.rugbyaholic.techshare.conf;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// ユーザの認証方式を決定するメソッド
		//メモリ内でユーザ管理　or　Database　orLDAP
		//ひとまずインメモリ
		auth.inMemoryAuthentication()
			.withUser("user").password(passwordEncoder().encode("password")).roles("USER");
	}
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// webアプリが管理しているリソースへのアクセス制御

		http.authorizeRequests()
			.anyRequest().authenticated()
			.and()
			.httpBasic();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		//パスワードをハッシュ化するメソッド
		return new BCryptPasswordEncoder();
	}
}
