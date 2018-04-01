package cn.yichao.security.app.authentication.social;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;
/**
 * 第三方登录过滤器
 * 
 * @author w4837
 *
 */
public class OpenIdAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
	// ~ Static fields/initializers
	// =====================================================================================

	public static final String PROJECT_OPENID_KEY = "openId";
	public static final String PROJECT_PROVIDERID_KEY = "providerId";

	private String openIdParameter = PROJECT_OPENID_KEY;
	private String providerIdParameter = PROJECT_PROVIDERID_KEY;
	private boolean postOnly = true;

	// ~ Constructors
	// ===================================================================================================
	/**
	 * 设置处理请求路径
	 */
	public OpenIdAuthenticationFilter() {
		super(new AntPathRequestMatcher("/authentication/social", "POST"));
	}

	// ~ Methods
	// ========================================================================================================

	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		if (postOnly && !request.getMethod().equals("POST")) {
			throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
		}

		String openId = obtainOpenId(request);

		if (openId == null) {
			openId = "";
		}
		openId = openId.trim();
		
		String providerId = obtainProviderId(request);

		if (providerId == null) {
			providerId = "";
		}
		providerId = providerId.trim();

		OpenIdAuthenticationToken authRequest = new OpenIdAuthenticationToken(openId,providerId);

		// Allow subclasses to set the "details" property
		setDetails(request, authRequest);

		return this.getAuthenticationManager().authenticate(authRequest);
	}

	/**
	 * Provided so that subclasses may configure what is put into the authentication
	 * request's details property.
	 *
	 * @param request
	 *            that an authentication request is being created for
	 * @param authRequest
	 *            the authentication request object that should have its details set
	 */
	protected void setDetails(HttpServletRequest request, OpenIdAuthenticationToken authRequest) {
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
	}

	/**
	 * Enables subclasses to override the composition of the Mobile, such as by
	 * including additional values and a separator.
	 *
	 * @param request
	 *            so that request attributes can be retrieved
	 *
	 * @return the Mobile that will be presented in the <code>Authentication</code>
	 *         request token to the <code>AuthenticationManager</code>
	 */
	protected String obtainOpenId(HttpServletRequest request) {
		return request.getParameter(openIdParameter);
	}
	protected String obtainProviderId(HttpServletRequest request) {
		return request.getParameter(providerIdParameter);
	}
 
	public void setOpenIdParameter(String openIdParameter) {
		Assert.hasText(openIdParameter, "Mobile parameter must not be empty or null");
		this.openIdParameter = openIdParameter;
	}
	public void setProviderIdParameter(String providerIdParameter) {
		Assert.hasText(openIdParameter, "Mobile parameter must not be empty or null");
		this.providerIdParameter = providerIdParameter;
	}

	/**
	 * Defines whether only HTTP POST requests will be allowed by this filter. If
	 * set to true, and an authentication request is received which is not a POST
	 * request, an exception will be raised immediately and authentication will not
	 * be attempted. The <tt>unsuccessfulAuthentication()</tt> method will be called
	 * as if handling a failed authentication.
	 * <p>
	 * Defaults to <tt>true</tt> but may be overridden by subclasses.
	 */
	public void setPostOnly(boolean postOnly) {
		this.postOnly = postOnly;
	}

	public final String getopenIdParameter() {
		return openIdParameter;
	}

	
	public final String getproviderIdParameter() {
		return openIdParameter;
	}
}
