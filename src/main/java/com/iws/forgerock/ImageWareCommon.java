package com.iws.forgerock;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import javax.security.auth.callback.Callback;

import org.forgerock.openam.auth.node.api.NodeProcessException;

import com.iwsinc.usermanager.exception.UserManagerCallFailedException;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;

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
	static final String IMAGEWARE_GMI_SERVER = "IMAGEWARE_GMI_SERVER";
	static final String IMAGEWARE_TENANT_NAME = "IMAGEWARE_TENANT_NAME";
	static final String IMAGEWARE_PARAM_APPLICATION_NAME = "IMAGEWARE_APPLICATION_NAME";
	static final String IMAGEWARE_VERIFY_URL = "IMAGEWARE_VERIFY_URL";
	static final String IMAGEWARE_APPLICATION_NAME = "ImageWare GoVerifyID/GMI";
	static final String MAIL_ATTRIBUTE = "mail";
	static final String IMAGEWARE_REGISTER_USER_TEXT = "IMAGEWARE_REGISTER_USER_TEXT";
	static final String IMAGEWARE_EMAIL_VALIDATION_TYPE = "email";
	

	private static String returnToLoginJS =
	"var fieldset = document.getElementById('content').getElementsByClassName('container')[0].getElementsByClassName('form')[0].getElementsByClassName('row')[0];" +
	"var link = document.createElement('a');" +
	"link.title = 'Return to Login Page';" +
	"link.style = 'text-align: center; display: block;';" +
	"link.href = '#login/&authIndexType=service&authIndexValue=ImageWare-Authentication';" + 
	"link.innerHTML = 'Return to Login Page';" +
	"fieldset.appendChild(link);";
	
	public static String getReturnToLoginJS()
	{
		return returnToLoginJS;
	}
	
	static UserManagerCallFailedException getUserManagerCallFailedException(String msg) {
		UserManagerCallFailedException e = new UserManagerCallFailedException();
		e.setMessageCode(msg);
		return e;
	}

	public static UnauthorizedException getUnauthorizedException(String message)
	{
		return new ImageWareCommon().new UnauthorizedException(message);
	}
	

	static String encodeEmailAddress(String emailAddress) throws NodeProcessException
	{
		String emailAddressEncoded = null;
		try
		{
			emailAddressEncoded = URLEncoder.encode(emailAddress, "UTF-8");
		}
		catch (UnsupportedEncodingException uee)
		{
			throw new NodeProcessException(uee.getLocalizedMessage());
		}
		return emailAddressEncoded;
	}


}
