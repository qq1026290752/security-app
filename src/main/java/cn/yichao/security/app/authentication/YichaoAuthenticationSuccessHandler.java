package cn.yichao.security.app.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.UnapprovedClientAuthenticationException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import cn.yichao.security.core.constant.ProjectConstant;
import lombok.extern.slf4j.Slf4j;

/**
 * 认证成功跳转
 * 
 * @author w4837
 *
 */
@Component(value = "yichaoAuthenticationSuccessHandler")
@Slf4j
public class YichaoAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

	@Autowired
	private ObjectMapper objectMapper; 
	@Autowired
	private ClientDetailsService clientDetailsService;
	@Autowired
	private AuthorizationServerTokenServices authorizationServerTokenServices;

	@Override
	public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
			Authentication authentication) throws IOException, ServletException {
		log.info("登陆成功");

		String header = httpServletRequest.getHeader("Authorization");
		//请求头包含Authorization 并且以"Basic "开始  
		if (header == null || !header.startsWith("Basic ")) {
			throw new UnapprovedClientAuthenticationException("请求头中无Authorization信息");
		}

		try {
			String[] tokens = extractAndDecodeHeader(header, httpServletRequest);
			assert tokens.length == 2;

			String clientId = tokens[0];
			String clientSecret = tokens[1];
			ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
			if(clientDetails == null) {
				throw new UnapprovedClientAuthenticationException("clientId:"+clientId+"对应的信息不存在。");
			}else if(!StringUtils.equals(clientSecret, clientDetails.getClientSecret())) {
				throw new UnapprovedClientAuthenticationException("clientId:"+clientId+"对应的信息不匹配。");
			}
			@SuppressWarnings("unchecked")
			TokenRequest tokenRequest = new TokenRequest(MapUtils.EMPTY_MAP, clientId, clientDetails.getScope(),"custom");
			
			OAuth2Request auth2Request = tokenRequest.createOAuth2Request(clientDetails);
			
			OAuth2Authentication auth2Authentication = new OAuth2Authentication(auth2Request, authentication);
			
			OAuth2AccessToken createAccessToken = authorizationServerTokenServices.createAccessToken(auth2Authentication);
			// 判断需要的返回类型
			httpServletResponse.setContentType(ProjectConstant.CONTENTTYPE_JSON);
			httpServletResponse.getWriter().write(objectMapper.writeValueAsString(createAccessToken));
		} catch (Exception e) {
			log.error(e.getMessage());
		}
	}

	/**
	 * 解析header中编码后的数据
	 * 
	 * @param header
	 * @param request
	 * @return
	 * @throws IOException
	 */
	private String[] extractAndDecodeHeader(String header, HttpServletRequest request) throws IOException {

		byte[] base64Token = header.substring(6).getBytes("UTF-8");
		byte[] decoded;
		try {
			decoded = Base64.decode(base64Token);
		} catch (IllegalArgumentException e) {
			throw new BadCredentialsException("Failed to decode basic authentication token");
		}

		String token = new String(decoded, "UTF-8");

		int delim = token.indexOf(":");

		if (delim == -1) {
			throw new BadCredentialsException("Invalid basic authentication token");
		}
		return new String[] { token.substring(0, delim), token.substring(delim + 1) };
	}

}
