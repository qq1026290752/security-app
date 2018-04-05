package cn.yichao.security.app; 
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.social.security.SpringSocialConfigurer;

import cn.yichao.security.app.authentication.social.OpenIdAuthentioncationSecurityConfig;
import cn.yichao.security.core.authentication.mobile.SmsAuthentioncationSecurityConfig;
import cn.yichao.security.core.authorize.AuthorizeConfigManager;
import cn.yichao.security.core.constant.ProjectConstant;
import cn.yichao.security.core.properties.SecurityPeoperties;
import cn.yichao.security.core.vlidate.ValidateCodeRepository;
import cn.yichao.security.core.vlidate.core.ValidateCodeFiler;
import cn.yichao.security.core.vlidate.core.sms.SmsValidateCodeFiler;

/**
 * 资源服务器
 * @author w4837
 *
 */
@Configuration
@EnableResourceServer
public class YichaoResourceServerConfig extends ResourceServerConfigurerAdapter{

	
	@Autowired
	private OpenIdAuthentioncationSecurityConfig openIdAuthentioncationSecurityConfig ;
	@Autowired
	private SecurityPeoperties securityPeoperties;
	@Autowired
	private AuthenticationSuccessHandler yichaoAuthenticationSuccessHandler;
	@Autowired
	private AuthenticationFailureHandler yichaoAuthenticationFailuHandler;
	@Autowired
	private SmsAuthentioncationSecurityConfig smsAuthentioncationSecurityConfig;
	@Autowired
	private SpringSocialConfigurer securitySocialConfigurer;
	@Autowired
	private ValidateCodeRepository appValidateCodeRepository;
	@Autowired
	private  AuthorizeConfigManager authorizeConfigManager;
	
	@Override
	public void configure(HttpSecurity http) throws Exception {
		//图片验证码
		 ValidateCodeFiler validateCodeFiler = new ValidateCodeFiler(appValidateCodeRepository); 
		 validateCodeFiler.setYichaoAuthenticationFailuHandler(yichaoAuthenticationFailuHandler);
		 validateCodeFiler.setSecurityPeoperties(securityPeoperties);
		 //短信验证码
		 SmsValidateCodeFiler smsValidateCodeFiler = new SmsValidateCodeFiler(appValidateCodeRepository); 
		 smsValidateCodeFiler.setYichaoAuthenticationFailuHandler(yichaoAuthenticationFailuHandler);
		 smsValidateCodeFiler.setSecurityPeoperties(securityPeoperties);
		 //调用前置方法
		 smsValidateCodeFiler.afterPropertiesSet();
		 http
		 	.addFilterBefore(validateCodeFiler, UsernamePasswordAuthenticationFilter.class)
		 	.addFilterBefore(smsValidateCodeFiler, UsernamePasswordAuthenticationFilter.class)
		 	.formLogin()
			 	.loginPage(ProjectConstant.LOGIN_JUMP_CONTROLLER)
			 	.loginProcessingUrl(ProjectConstant.LOGIN_URL)
			 	.successHandler(yichaoAuthenticationSuccessHandler)
			 	.failureHandler(yichaoAuthenticationFailuHandler)
			.and()
				//配置第三方联合登录
				.apply(securitySocialConfigurer)
			.and()
				.apply(openIdAuthentioncationSecurityConfig)
		 	.and()
		 		.csrf()
		 		.disable()
		 	.apply(smsAuthentioncationSecurityConfig);//加入手机验证码
		 authorizeConfigManager.config(http.authorizeRequests());
	}
}
