package cn.yichao.security.app;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.stereotype.Component;

import cn.yichao.security.core.constant.ProjectConstant;
import cn.yichao.security.core.social.YichaoSpringSocialConfigurer;
@Component
public class SpringSocialConfigurerPostProcessor implements BeanPostProcessor {

	@Override
	public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
		return bean;
	}

	/**
	 * 在App项目下Bean加载完成之后 替换掉默认的注册逻辑
	 */
	@Override
	public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
		if(StringUtils.equals(beanName, "securitySocialConfigurer")) {
			YichaoSpringSocialConfigurer securitySocialConfigurer = (YichaoSpringSocialConfigurer) bean;
			securitySocialConfigurer.signupUrl(ProjectConstant.SOCIAL_SIGNUP_URI);
			return securitySocialConfigurer;
		}
		return bean;
	}

}
 