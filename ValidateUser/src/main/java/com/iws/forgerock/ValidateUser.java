/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2018 ForgeRock AS.
 */

package com.iws.forgerock;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;


import java.util.ResourceBundle;

import javax.inject.Inject;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.CoreWrapper;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.iwsinc.usermanager.client.OauthBearerToken;
import com.iwsinc.usermanager.exception.UserManagerCallFailedException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.shared.debug.Debug;

/**
 * A node that verifies a user account exists in the ImageWare GoVerifyID user
 * repository
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class, configClass = ValidateUser.Config.class)
public class ValidateUser extends AbstractDecisionNode
{

	private static final String BUNDLE = "com/iws/forgerock/ValidateUser";
    private ResourceBundle bundle;
			
	private final Config config;
	private final CoreWrapper coreWrapper;
	private final static String DEBUG_FILE = "ValidateUser";
	protected Debug debug = Debug.getInstance(DEBUG_FILE);

	/**
	 * Configuration for the node.
	 */
	public interface Config
	{
		@Attribute(order = 100)
		default String tenantName()
		{
			return "";
		}

		@Attribute(order = 200)
		default String clientName()
		{
			return "";
		}

		@Attribute(order = 300)
		default String clientSecret()
		{
			return "";
		}

		@Attribute(order = 400)
		default String userManagerURL()
		{
			return "https://gmi-ha.iwsinc.com/usermanager";
		}

		@Attribute(order = 500)
		default String gmiServerURL()
		{
			return "https://gmi-ha.iwsinc.com/gmiserver";
		}

		@Attribute(order = 600)
		default String gmiApplicationName()
		{
			return "GoVerifyID";
		}

		@Attribute(order = 700)
		default String gmiTemplateName()
		{
			return "GVID_VERIFY_CHOICE";
		}

		@Attribute(order = 800)
		default String messageReason()
		{
			return "ForgeRock custom authentication test message";
		}
		
		@Attribute(order = 900)
		default int messageExpiresInSeconds()
		{
			return 180;
		}
	}

	/**
	 * Create the node.
	 * 
	 * @param config
	 *            The service config.
	 * @throws NodeProcessException
	 *             If the configuration was not valid.
	 */
	@Inject
	public ValidateUser(@Assisted Config config, CoreWrapper coreWrapper) throws NodeProcessException
	{
		this.config = config;
		this.coreWrapper = coreWrapper;
	}

	@Override
	public Action process(TreeContext context) throws NodeProcessException
	{

		debug.message("ValidateUser started");
		
		String emailAddress = "";
		String username = context.sharedState.get(USERNAME).asString();

		if (username == null || username.isEmpty())
		{
			debug.error("[" + DEBUG_FILE + "]: " + "Username not available.");
			return goTo(false).build();
		}
		debug.message("[" + DEBUG_FILE + "]: " + "Username {}.", username);

		AMIdentity userIdentity = coreWrapper.getIdentity(username, context.sharedState.get(REALM).asString());
		if (userIdentity == null)
		{
			debug.error("[" + DEBUG_FILE + "]: " + "Authentication failed in {}. User: '{}' does not exist.", Constants.IMAGEWARE_APPLICATION_NAME, username);
			return goTo(false).build();
		}
		
		try
		{
			if (userIdentity.getAttribute("mail").size() != 0)
			{
				// getting primary (first) email address for user
				emailAddress = userIdentity.getAttribute("mail").toArray()[0].toString();
				debug.message("[" + DEBUG_FILE + "]: " + "Email Address {}.", emailAddress);
			}
			else
			{
				debug.error("[" + DEBUG_FILE + "]: " + "Authentication failed in {}. User: '{}' has no email address in profile.", Constants.IMAGEWARE_APPLICATION_NAME, username);
				return goTo(false).build();
			}
		}
		catch (IdRepoException e)
		{
			debug.error("[" + DEBUG_FILE + "]: " + "Error locating user '{}' ", e);
			return goTo(false).build();
		}
		catch (SSOException e)
		{
			debug.error("[" + DEBUG_FILE + "]: " + "Error locating user '{}' ", e);
			return goTo(false).build();
		}

		String tenant = config.tenantName();
		String clientName = config.clientName();
		String clientSecret = config.clientSecret();
		String userManagerURL = config.userManagerURL();
		String gmiServerURL = config.gmiServerURL();
		String app = config.gmiApplicationName();
		String template = config.gmiTemplateName();
		String reasonText = config.messageReason();
		int messageExpiresInSeconds = config.messageExpiresInSeconds();

		userManagerURL += "/oauth/token?scope=ignored&grant_type=client_credentials";

		OauthBearerToken token = getOauthToken(clientName, clientSecret, userManagerURL);
		if (token != null)
		{
			
			Person person = validateUser(emailAddress, token, tenant, gmiServerURL);
			if (person != null)
			{
				debug.message("[" + DEBUG_FILE + "]: " + "validateUser returning true and moving to next step");

				String reason = reasonText;
				int expiresIn = messageExpiresInSeconds;
				String templatePath = gmiServerURL + "/tenant/" + tenant + "/app/" + app + "/template/" + template;
				String gmiMessageUrl = templatePath + "/person/" + person.getId() + "/message";

				String messageJson = "{" + "\"maxResponseAttempts\" : 3," + "\"template\" : \"" + templatePath + "\"," + "\"metadata\" :" + "{" + "\"reason\" :\"" + reason + "\"" + "}," + "\"expiresIn\" :" + expiresIn + "}";
				String verifyResponseUrlTemp = gmiServerURL + "/tenant/" + tenant + "/person/" + person.getId() + "/message/%s/response";

				debug.message("[" + DEBUG_FILE + "]: " + "IWS Message JSON: {} ", messageJson);
				
				if (biometricVerifyUser(context, person, token, gmiMessageUrl, verifyResponseUrlTemp, messageJson))
				{
					
					debug.message("[" + DEBUG_FILE + "]: " + "biometricVerifyUser returning true and completing authentication");
					return goTo(true).replaceSharedState(context.sharedState.copy().
							put(USERNAME, username).
							put(Constants.IMAGEWARE_OAUTH_BEARER_TOKEN, token.getAccessToken())).
							build();
				}
				else
				{
					debug.error("[" + DEBUG_FILE + "]: " + "User failed verification in {} for User '{}' of Tenant '{}'", Constants.IMAGEWARE_APPLICATION_NAME, username, tenant);
					return goTo(false).build();
				}
			}
			else
			{

				debug.error("[" + DEBUG_FILE + "]: " + "User not valid in {} for User '{}' of Tenant '{}'", Constants.IMAGEWARE_APPLICATION_NAME, username, tenant);
				return goTo(false).build();
			}
		}
		else
		{
			debug.error("[" + DEBUG_FILE + "]: " + "Oauth bearer token not set in {} for User '{}' of Tenant '{}'", Constants.IMAGEWARE_APPLICATION_NAME, username, tenant);
			return goTo(false).build();
		}

	}

	
	private boolean biometricVerifyUser(TreeContext context, Person person, OauthBearerToken token, String gmiMessageUrl, String gmiVerifyUrlTemp, String messageJson)
	{
		boolean returnValue = false;
		CloseableHttpResponse response = null;

		try
		{
			HttpPost httpPost = new HttpPost(gmiMessageUrl);
			httpPost.setHeader("Content-Type", "application/json");
			httpPost.setHeader("Authorization", "Bearer " + token.getAccessToken());

			httpPost.setEntity(new StringEntity(messageJson));

			CloseableHttpClient httpclient = HttpClients.createSystem();

			try
			{
				response = httpclient.execute(httpPost);
				if (response != null)
				{
					// get entity from response
					org.apache.http.HttpEntity entity = response.getEntity();

					String jsonResponse = EntityUtils.toString(entity);

					// investigate response for success/failure
					if (response.getStatusLine().getStatusCode() == org.apache.http.HttpStatus.SC_CREATED)
					{
						ObjectMapper objectMapper = new ObjectMapper();
						objectMapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
						Message message = objectMapper.readValue(jsonResponse, Message.class);
						
						if (message == null || message.getMessageId() == null)
						{
							debug.error("[" + DEBUG_FILE + "]: " + "biometricVerifyUser cannot read GMI Message");
							return false;
							
						}

						// share verification response url in state for retrieval later
						String verifyResponseUrl = String.format(gmiVerifyUrlTemp, message.getMessageId());
						context.sharedState.put(Constants.IMAGEWARE_VERIFY_URL, verifyResponseUrl);
						debug.message("[" + DEBUG_FILE + "]: " + "biometricVerifyUser returning true for sending message and moving to next step");
						
						return true;
					}
					else
					{
						debug.error("[" + DEBUG_FILE + "]: " + "GMI verification failed in {} error response: '{}: {}'", Constants.IMAGEWARE_APPLICATION_NAME, response.getStatusLine().getStatusCode(), response.getStatusLine().getReasonPhrase());
					}
				}
			}
			catch (Exception exp)
			{
				debug.error("[" + DEBUG_FILE + "]: " + "Exception in {} getBearerToken: '{}'", Constants.IMAGEWARE_APPLICATION_NAME, exp);
				throw exp;
			}

		}
		catch (Exception exp)
		{
			debug.error(exp.getMessage());
		}
		finally
		{
			if (response != null)
			{
				try
				{
					response.close();
				}
				catch (Throwable t)
				{
				}	
			}
		}

		return returnValue;
	}

	private Person validateUser(String username, OauthBearerToken token, String tenant, String gmiServerURL)
	{
		Person person = null;
		CloseableHttpResponse response = null;

		try
		{
			HttpGet httpGet = new HttpGet(gmiServerURL + "/person?userId=" + username);
			httpGet.setHeader("Content-Type", "application/json");
			httpGet.setHeader("Authorization", "Bearer " + token.getAccessToken());

			CloseableHttpClient httpclient = HttpClients.createSystem();

			try
			{
				response = httpclient.execute(httpGet);
				if (response != null)
				{
					// get entity from response
					org.apache.http.HttpEntity entity = response.getEntity();

					String jsonResponse = EntityUtils.toString(entity);

					// investigate response for success/failure
					if (response.getStatusLine().getStatusCode() == org.apache.http.HttpStatus.SC_OK)
					{
						ObjectMapper objectMapper = new ObjectMapper();
						objectMapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
						person = objectMapper.readValue(jsonResponse, Person.class);

						debug.message("[" + DEBUG_FILE + "]: " + "json from GMI: '{}'", jsonResponse);
					}
					else
					{
						UserManagerCallFailedException e = new UserManagerCallFailedException();
						String msg = String.format("Error in contacting UserManager. Status: %s", response.getStatusLine());
						e.setMessageCode(msg);
						throw e;
					}

					// and ensure it is fully consumed
					EntityUtils.consume(entity);
				}
				else
				{
					debug.error("[" + DEBUG_FILE + "]: " + "Error. No response from {}", Constants.IMAGEWARE_APPLICATION_NAME);
				}

			}
			catch (Exception exp)
			{
				debug.error("[" + DEBUG_FILE + "]: " + "Exception in {} validateUser: '{}'", Constants.IMAGEWARE_APPLICATION_NAME, exp);
				throw exp;
			}
		}
		catch (Exception exp)
		{
			debug.error(exp.getMessage());

		}
		finally
		{
			if (response != null)
			{
				try
				{
					response.close();
				}
				catch (Throwable t)
				{
				}
			}
		}

		return person;
	}

	private OauthBearerToken getOauthToken(String clientName, String clientSecret, String userManagerURL)
	{
		CloseableHttpResponse response = null;
		OauthBearerToken token = null;

		try
		{
			if (clientName != null && clientSecret != null)
			{
				String tokenString = clientName + ":" + clientSecret;
				String accessToken = new String(Base64.encodeBase64(tokenString.getBytes()));
				HttpGet httpGet = new HttpGet(userManagerURL);
				httpGet.setHeader("Content-Type", "application/x-www-form-urlencoded");
				httpGet.setHeader("Authorization", "Basic " + accessToken);

				CloseableHttpClient httpclient = HttpClients.createSystem();

				try
				{
					response = httpclient.execute(httpGet);
				}
				catch (Exception exp)
				{
					debug.error("[" + DEBUG_FILE + "]: " + "Exception in {} getBearerToken: '{}'", Constants.IMAGEWARE_APPLICATION_NAME, exp);
					throw exp;
				}

				if (response != null)
				{
					// get entity from response
					org.apache.http.HttpEntity entity = response.getEntity();

					String jsonResponse = EntityUtils.toString(entity);

					// investigate response for success/failure
					if (response.getStatusLine().getStatusCode() == org.apache.http.HttpStatus.SC_OK)
					{
						ObjectMapper objectMapper = new ObjectMapper();
						objectMapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
						token = objectMapper.readValue(jsonResponse, OauthBearerToken.class);
					}
					else
					{
						UserManagerCallFailedException e = new UserManagerCallFailedException();
						String msg = String.format("Error in contacting UserManager. Status: %s", response.getStatusLine());
						e.setMessageCode(msg);
						throw e;
					}

					// and ensure it is fully consumed
					EntityUtils.consume(entity);
				}
				else
				{
					debug.error("[" + DEBUG_FILE + "]: " + "Unable to get {} security info", Constants.IMAGEWARE_APPLICATION_NAME);
					UserManagerCallFailedException e = new UserManagerCallFailedException();
					String msg = String.format("Error in retrieving response from UserManager. Response is null");
					e.setMessageCode(msg);
					throw e;
				}
			}
			else
			{
				debug.error("[" + DEBUG_FILE + "]: " + "Unable to get {} security info", Constants.IMAGEWARE_APPLICATION_NAME);
				UserManagerCallFailedException e = new UserManagerCallFailedException();
				String msg = String.format("Error in contacting UserManager. Missing ClientName or ClientSecret");
				e.setMessageCode(msg);
				throw e;

			}
		}

		catch (Exception exp)
		{
			debug.error(exp.getMessage());

		}
		finally
		{
			if (response != null)
			{
				try
				{
					response.close();
				}
				catch (Throwable t)
				{
				}
			}
		}

		return token;
	}
}