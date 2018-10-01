package com.iws.forgerock;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.ResourceBundle;

import javax.security.auth.callback.TextOutputCallback;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.util.i18n.PreferredLocales;
import org.junit.Test;

import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;

public class ImageWareCommonTest
{
	
	static String username = "testXXX";

	static CoreWrapper coreWrapper = new CoreWrapper();		
	static ResourceBundle resourceBundle = (new PreferredLocales()).getBundleInPreferredLocale(ImageWareCommon.IMAGEWARE_INITIATOR_BUNDLE, ImageWareInitiator.class.getClassLoader());
	static JsonValue sharedState = new JsonValue(new HashMap<String, Object>());
	
	@Test
	public void testGetAMIdentityWithUsernameUnavailable()
	{

		username = "";
		ImageWareCommon.EmailObject emailObject = new ImageWareCommonStubUsernameUnavailable.EmailObject(coreWrapper, resourceBundle, sharedState, username).getEmailObject();
		
		NodeProcessException npe = null;
		String message = resourceBundle.getString("usernameNotAvailable");
		
		try
		{
			emailObject.emailToSharedState();
		}
		catch (NodeProcessException ex)
		{
			npe = ex;
		}
		
		assertEquals("NodeProcessExcpetion message not matching", message, npe.getMessage());
	}
	

	@Test
	public void testGetAMIdentityWithUserDoesNotExist()
	{

		ImageWareCommon.EmailObject emailObject = new ImageWareCommonStubNoUser.EmailObject(coreWrapper, resourceBundle, sharedState, username).getEmailObject();
		
		NodeProcessException npe = null;
		String message = String.format(resourceBundle.getString("userNotExist"), username);
		
		try
		{
			emailObject.emailToSharedState();
		}
		catch (NodeProcessException ex)
		{
			npe = ex;
		}
		
		assertEquals("NodeProcessExcpetion message not matching", message, npe.getMessage());
	}
	

	@Test
	public void testGetAMIdentityWithUserHasNoEmail()
	{

		ImageWareCommon.EmailObject emailObject = new ImageWareCommonStubUserNoEmail.EmailObject(coreWrapper, resourceBundle, sharedState, username).getEmailObject();
		
		NodeProcessException npe = null;
		String message = String.format(resourceBundle.getString("userNoEmailAddress"), username);
		
		try
		{
			emailObject.emailToSharedState();
		}
		catch (NodeProcessException ex)
		{
			npe = ex;
		}
		
		assertEquals("NodeProcessExcpetion message not matching", message, npe.getMessage());
	}
	
	/*
	 * Email is available case. No Callbacks created.
	 */
	@Test
	public void testEmailObjectWithEmailAvailable()
	{
		
		String emailAddress = username + "@domain.com";
		sharedState.put(ImageWareCommon.IMAGEWARE_USER_EMAIL, emailAddress);
		
		ImageWareCommon.EmailObject emailObject = new ImageWareCommon.EmailObject(coreWrapper, resourceBundle, sharedState, username).getEmailObject();

		assertNotNull("EmailObject should not be null", emailObject);
		assertEquals("Email Address does not match", emailObject.getEmailAddress(), emailAddress);
		assertEquals("Shared State does not match", sharedState, emailObject.getSharedState());
		assertNull("Callbacks should be null", emailObject.getCallbacks());
	
	}
	
	/*
	 * Email is unavailable case. Callbacks created.
	 */
	@Test
	public void testEmailObjectWithoutEmailAvailable()
	{
		
		List<TextOutputCallback> callbacks = new ArrayList<TextOutputCallback>();
		callbacks.add(new TextOutputCallback(0, ImageWareCommonStubNoEmail.EXCEPTION_MSG));
		callbacks.add(new ScriptTextOutputCallback(ImageWareCommon.getReturnToLoginJS()));

		ImageWareCommon.EmailObject emailObject = new ImageWareCommonStubNoEmail.EmailObject(coreWrapper, resourceBundle, sharedState, username).getEmailObject();
		
		assertNotNull("EmailObject should not be null", emailObject);
		assertEquals("Shared State does not match", sharedState, emailObject.getSharedState());
		assertNotNull("Callbacks should not be null", emailObject.getCallbacks());
		assertEquals("First TextOutputCallbacks Message should match", ((TextOutputCallback)emailObject.getCallbacks().get(0)).getMessage(), callbacks.get(0).getMessage());
		assertEquals("Second TextOutputCallbacks Message should match", ((TextOutputCallback)emailObject.getCallbacks().get(1)).getMessage(), callbacks.get(1).getMessage());
	
	}
	

	static class ImageWareCommonStubNoEmail extends ImageWareCommon
	{

		public static String EXCEPTION_MSG = "Email not available";

		static class EmailObject extends ImageWareCommon.EmailObject {
			

			@Override
			void emailToSharedState() throws NodeProcessException
			{
				throw new NodeProcessException(EXCEPTION_MSG);
			}
			

			EmailObject(CoreWrapper coreWrapper, ResourceBundle bundle, JsonValue sharedState, String username)
			{
				super(coreWrapper, bundle, sharedState, username);
			}

		}
	}
	
	static class ImageWareCommonStubNoUser extends ImageWareCommon
	{

		public static String EXCEPTION_MSG = resourceBundle.getString("userNotExist");

		static class EmailObject extends ImageWareCommon.EmailObject {
		
			private String username;

			@Override
			void emailToSharedState() throws NodeProcessException
			{
				throw new NodeProcessException(String.format(EXCEPTION_MSG, username));
			}
			

			EmailObject(CoreWrapper coreWrapper, ResourceBundle bundle, JsonValue sharedState, String username)
			{
				super(coreWrapper, bundle, sharedState, username);
				this.username = username;
			}

		}
	}

	static class ImageWareCommonStubUsernameUnavailable extends ImageWareCommon
	{

		public static String EXCEPTION_MSG = resourceBundle.getString("usernameNotAvailable");

		static class EmailObject extends ImageWareCommon.EmailObject {
		

			@Override
			void emailToSharedState() throws NodeProcessException
			{
				throw new NodeProcessException(EXCEPTION_MSG);
			}
			

			EmailObject(CoreWrapper coreWrapper, ResourceBundle bundle, JsonValue sharedState, String username)
			{
				super(coreWrapper, bundle, sharedState, username);
			}

		}
	}
	
	static class ImageWareCommonStubUserNoEmail extends ImageWareCommon
	{

		public static String EXCEPTION_MSG = resourceBundle.getString("userNoEmailAddress");

		static class EmailObject extends ImageWareCommon.EmailObject {
		
			private String username;

			@Override
			void emailToSharedState() throws NodeProcessException
			{
				throw new NodeProcessException(String.format(EXCEPTION_MSG, username));
			}
			

			EmailObject(CoreWrapper coreWrapper, ResourceBundle bundle, JsonValue sharedState, String username)
			{
				super(coreWrapper, bundle, sharedState, username);
				this.username = username;
			}

		}
	}
}
