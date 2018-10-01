package com.iws.forgerock;

import com.iwsinc.usermanager.client.OauthBearerToken;
import com.iwsinc.usermanager.client.UserManagerClient;

public class OauthService
{
	private UserManagerClient userManagerClient;
	private String clientName;
	private String clientSecret;
	private String userManagerServerUrl;
	
	public OauthService(String userManagerServerUrl, String clientName, String clientSecret)
	{
		this.userManagerServerUrl = userManagerServerUrl;
		this.clientName = clientName;
		this.clientSecret = clientSecret;
		
		userManagerClient = new UserManagerClient();
	}
	

	public OauthBearerToken getOauthToken()
	{
		return userManagerClient.getBearerToken(userManagerServerUrl, clientName, clientSecret);
	}
}
