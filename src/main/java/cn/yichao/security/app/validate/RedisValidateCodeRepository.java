package cn.yichao.security.app.validate;

import java.util.concurrent.TimeUnit;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.ServletWebRequest;

import cn.yichao.security.core.vlidate.ValidateCode;
import cn.yichao.security.core.vlidate.ValidateCodeRepository;
import cn.yichao.security.core.vlidate.core.ValidataCodeException;
/**
 * app验证码校验
 * @author w4837
 *
 */
@Component("appValidateCodeRepository")
public class RedisValidateCodeRepository implements ValidateCodeRepository {

	@Autowired
	private RedisTemplate<Object, Object> redisTemplate;
	
	@Override
	public void save(ServletWebRequest request, ValidateCode validateCode, String validateCodeKey) {
		redisTemplate.opsForValue().set(buildKey(request, validateCodeKey), validateCode , 30,TimeUnit.MINUTES);
	}

	@Override
	public ValidateCode get(ServletWebRequest request, String validateCodeKey) {
		// TODO Auto-generated method stub
		Object object = redisTemplate.opsForValue().get(buildKey(request, validateCodeKey));
		if(object == null) {
			return null;
		}
		return (ValidateCode) object;
	}

	@Override
	public void remove(ServletWebRequest request, String validateCodeKey) {
		redisTemplate.delete(buildKey(request, validateCodeKey));
	}
	
	public String buildKey(ServletWebRequest request,String validateCodeKey) {
		//设备ID
		String deviceId = request.getHeader("deviceId");
		if(StringUtils.isBlank(deviceId)) {
			throw new ValidataCodeException("请求头携带的deviceId不能为空");
		}
		return "code:"+validateCodeKey+":" + deviceId; 
	}

}
