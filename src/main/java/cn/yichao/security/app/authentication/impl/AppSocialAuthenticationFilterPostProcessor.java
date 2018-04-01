package cn.yichao.security.app.authentication.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.social.security.SocialAuthenticationFilter;
import org.springframework.stereotype.Component;

import cn.yichao.security.core.social.SocialAuthenticationFilterPostProcessor;

@Component
public class AppSocialAuthenticationFilterPostProcessor implements SocialAuthenticationFilterPostProcessor {

	@Autowired
	private AuthenticationSuccessHandler yichaoAuthenticationSuccessHandler;
	
 	@Override
	public void proessor(SocialAuthenticationFilter authenticationFilter) {
		authenticationFilter.setAuthenticationSuccessHandler(yichaoAuthenticationSuccessHandler);
	}

}
