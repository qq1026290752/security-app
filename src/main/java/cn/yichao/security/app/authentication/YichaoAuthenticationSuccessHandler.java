package cn.yichao.security.app.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import cn.yichao.security.core.constant.ProjectConstant;
import cn.yichao.security.core.properties.LoginType;
import cn.yichao.security.core.properties.SecurityPeoperties;
import lombok.extern.slf4j.Slf4j;
/**
 * 认证成功跳转
 * @author w4837
 *
 */
@Component(value = "yichaoAuthenticationSuccessHandler")
@Slf4j
public class YichaoAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

	@Autowired
	private ObjectMapper objectMapper;
	@Autowired
	private SecurityPeoperties securityPeoperties;
	
	@Override
	public void onAuthenticationSuccess(HttpServletRequest httpServletRequest,
					HttpServletResponse httpServletResponse, Authentication authentication)
			throws IOException, ServletException {
		log.info("登陆成功");
		//判断需要的返回类型
		if(LoginType.JSON.equals(securityPeoperties.getBrowser().getLoginType())) {
			httpServletResponse.setContentType(ProjectConstant.CONTENTTYPE_JSON);
			httpServletResponse.getWriter().write(objectMapper.writeValueAsString(authentication));		
		}else {
			super.onAuthenticationSuccess(httpServletRequest, httpServletResponse, authentication);
		}
	
	}

}
