package cn.yichao.security.app.social;

import java.util.concurrent.TimeUnit;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.social.connect.Connection;
import org.springframework.social.connect.ConnectionData;
import org.springframework.social.connect.ConnectionFactoryLocator;
import org.springframework.social.connect.UsersConnectionRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.WebRequest;

import cn.yichao.security.app.exception.AppSecurityException;

@Component
public class AppSignInUtils {

	@Autowired
	private RedisTemplate<Object, Object> redisTemplate;
	
	@Autowired
	private UsersConnectionRepository usersConnectionRepository;
	@Autowired
	private ConnectionFactoryLocator connectionFactoryLocator;
	
	public void saveConnectionData(WebRequest request,ConnectionData connectionData) {
		redisTemplate.opsForValue().set(getKey(request), connectionData, 10, TimeUnit.MINUTES);
	}
	
	public void doPostSignUp(WebRequest webRequest,String userId) {
		String key = getKey(webRequest);
		if(!redisTemplate.hasKey(key)) {
			throw new AppSecurityException("无法找到用户第三方用户");
		}
		ConnectionData connectionData = (ConnectionData) redisTemplate.opsForValue().get(key);
		Connection<?> connection = connectionFactoryLocator.getConnectionFactory(connectionData.getProviderId()).createConnection(connectionData);
		usersConnectionRepository.createConnectionRepository(userId).addConnection(connection);
		redisTemplate.delete(key);
	}
	
	
	private String getKey(WebRequest request) {
		 String deviceId = request.getHeader("deviceId");
		 if(StringUtils.isBlank(deviceId)) {
			 throw new AppSecurityException("请传入设备ID");
		 }
		return "yichao:security.social.connect:" + deviceId;
	}
}
