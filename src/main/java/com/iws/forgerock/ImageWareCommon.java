package com.iws.forgerock;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;

import com.iplanet.sso.SSOException;
import com.iwsinc.usermanager.exception.UserManagerCallFailedException;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Iterator;
import java.util.List;
import java.util.ResourceBundle;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.TextOutputCallback;
import org.apache.commons.lang.StringUtils;
import org.forgerock.guava.common.collect.ImmutableList;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.core.CoreWrapper;

class ImageWareCommon {


	class UnauthorizedException extends Exception {

		UnauthorizedException(String message) {
			super(message);
		}
	}
	static final String IMAGEWARE_INITIATOR_BUNDLE = "com/iws/forgerock/ImageWareInitiator";

	static final String IMAGEWARE_SHOULD_CHECK = "IMAGEWARE_SHOULD_CHECK";
	static final String IMAGEWARE_OAUTH_BEARER_TOKEN = "IMAGEWARE_OAUTH_BEARER_TOKEN";
	static final String IMAGEWARE_GMI_SERVER = "IMAGEWARE_GMI_SERVER";
	static final String IMAGEWARE_TENANT_NAME = "IMAGEWARE_TENANT_NAME";
	static final String IMAGEWARE_PARAM_APPLICATION_NAME = "IMAGEWARE_APPLICATION_NAME";
	static final String IMAGEWARE_VERIFY_URL = "IMAGEWARE_VERIFY_URL";
	static final String IMAGEWARE_APPLICATION_NAME = "ImageWare GoVerifyID/GMI";
	static final String IMAGEWARE_EMAIL_VALIDATION_TYPE = "email";
	static final String IMAGEWARE_USER_EMAIL = "IMAGEWARE_USER_EMAIL";
	private static final String MAIL_ATTRIBUTE = "mail";


	static String getReturnToLoginJS() {
		return "var fieldset = document.getElementById('content').getElementsByClassName" +
					"('container')[0].getElementsByClassName('form')[0].getElementsByClassName('row')[0];" +
					"var link = document.createElement('a');" +
					"link.title = 'Return to Login Page';" +
					"link.style = 'text-align: center; display: block;';" +
					"link.href = 'javascript:window.location.reload(true)';" +
					"link.innerHTML = 'Return to Login Page';" +
					"fieldset.appendChild(link);" +
					"document.getElementById('loginButton_0').style.display = 'none';";
	}
	
	static UserManagerCallFailedException getUserManagerCallFailedException(String msg) {
		UserManagerCallFailedException e = new UserManagerCallFailedException();
		e.setMessageCode(msg);
		return e;
	}

	static UnauthorizedException getUnauthorizedException(String message) { return new ImageWareCommon().new
			UnauthorizedException(message); }
	

	static String encodeEmailAddress(String emailAddress) throws NodeProcessException {
		String emailAddressEncoded;
		try {
			emailAddressEncoded = URLEncoder.encode(emailAddress, "UTF-8");
		} catch (UnsupportedEncodingException uee) {
			throw new NodeProcessException(uee.getLocalizedMessage());
		}
		return emailAddressEncoded;
	}

	private static AMIdentity getAmIdentity(CoreWrapper coreWrapper, ResourceBundle bundle, JsonValue sharedState,
											String
			username) throws NodeProcessException {
		String errorMessage;

		if (StringUtils.isEmpty(username)) {
			errorMessage = bundle.getString("usernameNotAvailable");
			throw new NodeProcessException(errorMessage);
		}
		
		AMIdentity userIdentity = null;
		try {
			userIdentity = coreWrapper.getIdentity(username, coreWrapper.convertRealmPathToRealmDn(
				sharedState.get(REALM).asString()));
		} 
		catch (Throwable e)
		{
			throw new NodeProcessException(e.getClass() + " " + e.getLocalizedMessage());
		}
		
		if (userIdentity == null) {
			errorMessage = String.format(bundle.getString("userNotExist"), username);
			throw new NodeProcessException(errorMessage);
		}
		return userIdentity;
	}

	private static String getUserEmail(AMIdentity userIdentity, ResourceBundle bundle) throws NodeProcessException {
		Iterator<String> emailAddressIterator;
		try {
			emailAddressIterator = userIdentity.getAttribute(MAIL_ATTRIBUTE).iterator();
		} catch (IdRepoException | SSOException e) {
			throw new NodeProcessException(e);
		}

		if (!emailAddressIterator.hasNext()) {
			String errorMessage = String.format(bundle.getString("userNoEmailAddress"), userIdentity.getName());
			throw new NodeProcessException(errorMessage);
		}
		// getting primary (first) email address for user
		return emailAddressIterator.next();
	}

	static class EmailObject {
		private boolean exception;
		private CoreWrapper coreWrapper;
		private ResourceBundle bundle;
		private JsonValue sharedState;
		private String username;
		private String emailAddress;
		private List<Callback> callbacks;

		EmailObject(CoreWrapper coreWrapper, ResourceBundle bundle, JsonValue sharedState, String username) {
			this.coreWrapper = coreWrapper;
			this.bundle = bundle;
			this.sharedState = sharedState;
			this.username = username;
		}

		boolean isException() {
			return exception;
		}

		String getEmailAddress() {
			return emailAddress;
		}

		JsonValue getSharedState() {
			return sharedState;
		}

		List<Callback> getCallbacks() {
			return callbacks;
		}

		EmailObject getEmailObject() {
			if (sharedState.isDefined(ImageWareCommon.IMAGEWARE_USER_EMAIL)) {
				emailAddress = sharedState.get(ImageWareCommon.IMAGEWARE_USER_EMAIL).asString();
			} else {
				try {
					emailToSharedState();
				} catch (NodeProcessException ex) {
					callbacks = ImmutableList.of(new TextOutputCallback(0, ex.getMessage()), new
							ScriptTextOutputCallback(ImageWareCommon.getReturnToLoginJS()));
					exception = true;
					return this;
				}
			}
			exception = false;
			return this;
		}

		void emailToSharedState() throws NodeProcessException
		{
			emailAddress = getUserEmail(getAmIdentity(coreWrapper, bundle, sharedState, username), bundle);
			sharedState.add(ImageWareCommon.IMAGEWARE_USER_EMAIL, emailAddress);
		}
	}
}
