package cn.yichao.security.app.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import com.fasterxml.jackson.databind.ObjectMapper;

import cn.yichao.security.core.constant.ProjectConstant;
import cn.yichao.security.core.properties.LoginType;
import cn.yichao.security.core.properties.SecurityPeoperties;
import cn.yichao.security.core.support.SimpleResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component("yichaoAuthenticationFailuHandler")
public class YichaoAuthenticationFailuHandler extends SimpleUrlAuthenticationFailureHandler{

	@Autowired
	private ObjectMapper objectMapper;
	@Autowired
	private SecurityPeoperties securityPeoperties;
	
	@Override
	public void onAuthenticationFailure(HttpServletRequest request
			, HttpServletResponse response, AuthenticationException exception)
			throws IOException, ServletException {
		log.info("登录失败");
		if(LoginType.JSON.equals(securityPeoperties.getBrowser().getLoginType())) {
			response.setContentType(ProjectConstant.CONTENTTYPE_JSON);
			response.getWriter().write(objectMapper.writeValueAsString(new SimpleResponse(exception.getMessage())));	
		}else {
			super.onAuthenticationFailure(request, response, exception);
		}
	}

}
