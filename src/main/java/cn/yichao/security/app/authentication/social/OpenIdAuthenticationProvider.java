package cn.yichao.security.app.authentication.social;
 
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.collections.CollectionUtils;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.social.connect.UsersConnectionRepository;
import lombok.Getter;
import lombok.Setter;

public class OpenIdAuthenticationProvider implements AuthenticationProvider {

	@Getter
	@Setter
	private  UserDetailsService userDetailsService;
	
	@Getter
	@Setter
	private  UsersConnectionRepository usersConnectionRepository;
	
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OpenIdAuthenticationToken authenticationToken = (OpenIdAuthenticationToken) authentication;
		//拿到全部第三方登录信息
		Set<String> providerUserIds = new HashSet<>();
		
		providerUserIds.add((String) authenticationToken.getPrincipal());
		
		Set<String> userIds = usersConnectionRepository.findUserIdsConnectedTo(authenticationToken.getProviderId(), providerUserIds);
		
		if(CollectionUtils.isEmpty(userIds)|| userIds.size()!=1) {
			//认证失败
			throw new InternalAuthenticationServiceException("无法获取到用户信息");
		}
		String userId = userIds.iterator().next();
		UserDetails userDetails = userDetailsService.loadUserByUsername(userId);
		if(userDetails == null) {
			//认证失败
			throw new InternalAuthenticationServiceException("無法讀取用户信息");
		}
		//认证成功
		OpenIdAuthenticationToken openIdAuthenticationToken = new OpenIdAuthenticationToken(userDetails, userDetails.getAuthorities());
		openIdAuthenticationToken.setDetails(authenticationToken.getDetails());
		return openIdAuthenticationToken;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		//判断是否为三方登录token
		return OpenIdAuthenticationToken.class.isAssignableFrom(authentication);
	}

}