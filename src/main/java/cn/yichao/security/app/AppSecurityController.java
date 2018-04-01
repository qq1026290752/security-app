package cn.yichao.security.app;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.social.connect.Connection;
import org.springframework.social.connect.ConnectionData;
import org.springframework.social.connect.web.ProviderSignInUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.ServletWebRequest;

import cn.yichao.security.app.social.AppSignInUtils;
import cn.yichao.security.core.constant.ProjectConstant;
import cn.yichao.security.core.support.SocialUserInfo;
 

@RestController
public class AppSecurityController {

	@Autowired
	private ProviderSignInUtils providerSignInUtils;
	@Autowired
	private AppSignInUtils appSignInUtils;
	
	@GetMapping(ProjectConstant.SOCIAL_SIGNUP_URI)
	@ResponseStatus(code = HttpStatus.UNAUTHORIZED)
	public SocialUserInfo getSocialUserInfo(HttpServletRequest request) {
		SocialUserInfo socialUserInfo = new SocialUserInfo();
		Connection<?> connection = providerSignInUtils.getConnectionFromSession(new ServletWebRequest(request));
		socialUserInfo.setProviderId(connection.getKey().getProviderId());
		socialUserInfo.setProviderUserId(connection.getKey().getProviderUserId());
		socialUserInfo.setNikeName(connection.getDisplayName());
		socialUserInfo.setHeadUrl(connection.getImageUrl());
		//用户信息转存到 redis里面
		appSignInUtils.saveConnectionData(new ServletWebRequest(request), connection.createData());
		return socialUserInfo;
	}
}
