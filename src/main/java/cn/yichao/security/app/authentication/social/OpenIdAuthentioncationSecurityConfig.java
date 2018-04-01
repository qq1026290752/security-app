package cn.yichao.security.app.authentication.social;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.social.connect.UsersConnectionRepository;
import org.springframework.stereotype.Component;

@Component
public class OpenIdAuthentioncationSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

	@Autowired
	private AuthenticationSuccessHandler yichaoAuthenticationSuccessHandler;
	@Autowired
	private AuthenticationFailureHandler yichaoAuthenticationFailuHandler;
	@Autowired
	private UserDetailsService userDetailsService;
	@Autowired
	private UsersConnectionRepository usersConnectionRepository;
	
	@Override
	public void configure(HttpSecurity http) throws Exception {
		OpenIdAuthenticationFilter openIdAuthenticationFilter = new OpenIdAuthenticationFilter();
		openIdAuthenticationFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
		//成功跳转
		openIdAuthenticationFilter.setAuthenticationSuccessHandler(yichaoAuthenticationSuccessHandler);
		//失败跳转
		openIdAuthenticationFilter.setAuthenticationFailureHandler(yichaoAuthenticationFailuHandler);
		//
		OpenIdAuthenticationProvider openIdAuthenticationProvider = new OpenIdAuthenticationProvider();
		openIdAuthenticationProvider.setUsersConnectionRepository(usersConnectionRepository);
		openIdAuthenticationProvider.setUserDetailsService(userDetailsService);
		http.authenticationProvider(openIdAuthenticationProvider)
			.addFilterAfter(openIdAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);//短信验证码加入过滤器
	}
}
