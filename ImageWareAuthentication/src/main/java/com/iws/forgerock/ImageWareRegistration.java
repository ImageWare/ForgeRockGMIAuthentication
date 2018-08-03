/*
Ï * The contents of this file are subject to the terms of the Common Development and
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

import java.util.List;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.TextOutputCallback;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.forgerock.guava.common.collect.ImmutableList;
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
 * A node that creates a User in ImageWare's GoVerifyID backend for mobile biometric enrollment and verification
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class, configClass = ImageWareRegistration.Config.class)
public class ImageWareRegistration extends AbstractDecisionNode
{

	private final Config config;
	private final CoreWrapper coreWrapper;
	private final static String DEBUG_FILE = "ImageWareRegistration";
	protected Debug debug = Debug.getInstance(DEBUG_FILE);
	
	private String gmiServerURL;
	private String userManagerURL;
	private OauthBearerToken bearerToken;
	
	String getGmiServerURL()
	{
		return gmiServerURL;
	}

	void setGmiServerURL(String gmiServerUrl)
	{
		this.gmiServerURL = gmiServerUrl;
	}
	
	private String getUserManagerURL()
	{
		return userManagerURL;
	}

	private void setUserManagerURL(String userManagerUrl)
	{
		this.userManagerURL = userManagerUrl;
	}

	private OauthBearerToken getBearerToken()
	{
		return bearerToken;
	}

	private void setBearerToken(OauthBearerToken bearerToken)
	{
		this.bearerToken = bearerToken;
	}

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
		default String applicationName()
		{
			return "GoVerifyID";
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
	public ImageWareRegistration(@Assisted Config config, CoreWrapper coreWrapper) throws NodeProcessException
	{
		this.config = config;
		this.coreWrapper = coreWrapper;
	}

	@Override
	public Action process(TreeContext context) throws NodeProcessException
	{

		// NOTE: The user being registered is a Person entity in GMI
	

		// Need both username and email from user interface
		//String username = context.sharedState.get(USERNAME).asString();		
		//String email = context.sharedState.get(EMAIL_ADDRESS).asString();
		
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
		
		
		
		
		// Step 1: authorize oauth client

		String tenant = config.tenantName();
		String applicationName = config.applicationName();
		String clientName = config.clientName();
		String clientSecret = config.clientSecret();

		setGmiServerURL(config.gmiServerURL());
		setUserManagerURL(config.userManagerURL() + "/oauth/token?scope=ignored&grant_type=client_credentials");
		

		OauthBearerToken token = getGmiOauthToken(clientName, clientSecret);
		if (token != null)
		{
			setBearerToken(token);
			
			// Step 2: add GMI person 
			Person userAdded = addUserAsPersonToGmi(emailAddress, tenant);
			
			if (userAdded != null)
			{				
				// Step 3: user needs to download GoVerifyID app and register with email address
				//	upon success, user will get a registration email
				//	after completing the registration step, the user will receive an Enroll Message on their mobile device
					
				
				// If the GMI TenantApplication.validationType property is set to "email" then this user will be able to self-register
				// Otherwise the user must wait for Tenant Admin to finalize the registration process
				String userRegisterInfo = "Registration will continue once you have downloaded the " + applicationName + " mobile app and added your email address as your username.";
						
				Application application = getTenantApplication(tenant, applicationName);
				if (application != null)
				{	
					if (! application.getValidationType().equals(Constants.IMAGEWARE_EMAIL_VALIDATION_TYPE))
					{
						userRegisterInfo = "Your Tenant Application requires further action by your Tenant Administrator before you can continue with registration. Please contact your Tenant Administrator for assistance.";
					}
				
					//AMIdentity userIdentity = coreWrapper.getIdentity(username, context.sharedState.get(REALM).asString());
					//AMIdentity userIdentity = coreWrapper.createIdentity
					
					Action.ActionBuilder registerResult = this.goTo(true);
					final List<Callback> callbacks = (List<Callback>) ImmutableList.of((Callback) new TextOutputCallback(0, userRegisterInfo));
					registerResult = Action.send(callbacks);
					
					return registerResult.build();
				}
				else
				{
					debug.error("[" + DEBUG_FILE + "]: " + "Application entity could not be retrieved. User could not be added as a Person in {} for User '{}' of Tenant '{}'", Constants.IMAGEWARE_APPLICATION_NAME, username, tenant);
					return goTo(false).build();
				}
			}
			else
			{
				debug.error("[" + DEBUG_FILE + "]: " + "User could not be added as Person in {} for User '{}' of Tenant '{}'", Constants.IMAGEWARE_APPLICATION_NAME, username, tenant);
				return goTo(false).build();
			}
		}
		else
		{
			debug.error("[" + DEBUG_FILE + "]: " + "Oauth bearer token not set in {} for User '{}' of Tenant '{}'", Constants.IMAGEWARE_APPLICATION_NAME, username, tenant);
			return goTo(false).build();
		}
	}
	
	private Application getTenantApplication(String tenant, String applicationName)
	{
		Application application = null;
		CloseableHttpResponse response = null;
		OauthBearerToken token = getBearerToken();

		try
		{
			HttpGet httpGet = new HttpGet(gmiServerURL + "/tenant/" + tenant + "/app/" + applicationName);
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
						application = objectMapper.readValue(jsonResponse, Application.class);

						debug.message("[" + DEBUG_FILE + "]: " + "json from GMI server: '{}'", jsonResponse);
					}
					else
					{
						UserManagerCallFailedException e = new UserManagerCallFailedException();
						String msg = String.format("Error in contacting GMI Server. Status: %s", response.getStatusLine());
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
				debug.error("[" + DEBUG_FILE + "]: " + "Exception in {} getTenantApplication: '{}'", Constants.IMAGEWARE_APPLICATION_NAME, exp.getMessage());
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

		return application;
	}

	
	private Person addUserAsPersonToGmi(String emailAddress, String tenant)
	{
		Person person = null;
		CloseableHttpResponse response = null;
		OauthBearerToken token = getBearerToken();
	
		String gmiUrl = getGmiServerURL() + "/tenant/" + tenant + "/person";

		try
		{

			HttpPost httpPost = new HttpPost(gmiUrl);
			httpPost.setHeader("Content-Type", "application/json");
			httpPost.setHeader("Authorization", "Bearer " + token.getAccessToken());

			String messageJson = "{" + "\"userId\" : \"" + emailAddress + "\" }";
			
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
					if (response.getStatusLine().getStatusCode() == org.apache.http.HttpStatus.SC_CONFLICT)
					{
						debug.error("[" + DEBUG_FILE + "]: " + "Error in {}. User with email address {} already exists in tenant {}", Constants.IMAGEWARE_APPLICATION_NAME, emailAddress, tenant);
					}
					else if (response.getStatusLine().getStatusCode() == org.apache.http.HttpStatus.SC_CREATED)
					{
						ObjectMapper objectMapper = new ObjectMapper();
						objectMapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
						person = objectMapper.readValue(jsonResponse, Person.class);
					}
					else
					{
						String msg = String.format("Cannot add user. Status: %s", response.getStatusLine());
						debug.error(msg);
					}
					
				}
			}
			catch (Exception exp)
			{
				debug.error("[" + DEBUG_FILE + "]: " + "Exception in {} addUserAsPersonToGmi: '{}'", Constants.IMAGEWARE_APPLICATION_NAME, exp);
				throw exp;
			}
		}
		catch (Exception exp)
		{
			debug.error(exp.getMessage());
		}
		
		return person;
	}
	
	private OauthBearerToken getGmiOauthToken(String clientName, String clientSecret)
	{
		CloseableHttpResponse response = null;
		OauthBearerToken token = null;
		String userManagerURL = getUserManagerURL();

		try
		{
			if (clientName != null && clientSecret != null)
			{
				String tokenString = clientName + ":" + clientSecret;
				String basicToken = new String(Base64.encodeBase64(tokenString.getBytes()));
				HttpGet httpGet = new HttpGet(userManagerURL);
				httpGet.setHeader("Content-Type", "application/x-www-form-urlencoded");
				httpGet.setHeader("Authorization", "Basic " + basicToken);

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
