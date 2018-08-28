package com.iws.forgerock;

import com.iwsinc.usermanager.exception.UserManagerCallFailedException;

public class ImageWareCommon
{

	public class UnauthorizedException extends Exception
	{
		public UnauthorizedException(Throwable t)
		{
			super(t);
		}
		
		public UnauthorizedException(String message)
		{
			super(message);
		}
	}

	static final String IMAGEWARE_OAUTH_BEARER_TOKEN = "IMAGEWARE_OAUTH_BEARER_TOKEN";
	static final String IMAGEWARE_VERIFY_URL = "IMAGEWARE_VERIFY_URL";
	static final String IMAGEWARE_APPLICATION_NAME = "ImageWare GoVerifyID/GMI";
	static final String MAIL_ATTRIBUTE = "mail";
	static final String IMAGEWARE_REGISTER_USER_TEXT = "IMAGEWARE_REGISTER_USER_TEXT";
	static final String IMAGEWARE_EMAIL_VALIDATION_TYPE = "email";
	
	static UserManagerCallFailedException getUserManagerCallFailedException(String msg) {
		UserManagerCallFailedException e = new UserManagerCallFailedException();
		e.setMessageCode(msg);
		return e;
	}

	public static UnauthorizedException getUnauthorizedException(String message)
	{
		return new ImageWareCommon().new UnauthorizedException(message);
	}
}
