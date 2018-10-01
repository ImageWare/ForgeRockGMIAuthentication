package com.iws.forgerock;

import org.forgerock.openam.auth.node.api.NodeProcessException;

import com.iwsinc.usermanager.client.OauthBearerToken;

class TokenService {
	
	private static class TokenServiceHelper {
		private static final TokenService INSTANCE = new TokenService();
	}
	    
    static TokenService getInstance() {
    	return TokenServiceHelper.INSTANCE;
    }
     
    private static OauthService oauthService = null;
 	private OauthBearerToken bearerToken = null;
 	private long tokenExpiresAt;
 	private static String clientName;
 	private static String clientSecret;
 	private static char[] clientSecretRaw;
 	private static String userManagerURL;
	

	static void setOauthService(OauthService oauthServiceIn)
	{
		oauthService = oauthServiceIn;
	}

	OauthBearerToken getBearerToken() throws NodeProcessException {
 		if (bearerToken == null || isTokenExpired()) storeOauthToken();
 		return bearerToken;
 	}

 	void setBearerToken(OauthBearerToken bearerToken) { this.bearerToken = bearerToken; }

 	private long getTokenExpiresAt() { return tokenExpiresAt; }

 	private void setTokenExpiresAt(long tokenExpiresAt) { this.tokenExpiresAt = tokenExpiresAt; }
 	
	static void setConfig(ImageWareInitiator.Config config) {
		
/*		// reset Bearer Token if content changes
		if ((clientName != null && clientName != config.clientName()) ||
			(clientSecretRaw != null && clientSecretRaw != config.clientSecret()) ||
			(userManagerURL != null && userManagerURL != config.userManagerURL())) {
			
			setBearerToken(null);
		}
*/			
		clientName = config.clientName();
		clientSecretRaw = config.clientSecret();
		clientSecret = (clientSecretRaw != null) ? new String(clientSecretRaw) : "";
		userManagerURL = config.userManagerURL();
		
		setOauthService(new OauthService(userManagerURL, clientName, clientSecret));
	}
	
	boolean isTokenExpired() {
		return getTokenExpiresAt() <= System.currentTimeMillis() / 1000;
	}
	
    private void storeOauthToken() throws
			NodeProcessException {
    	
    	try {
			OauthBearerToken token = oauthService.getOauthToken();
			long expiresAt = token.getExpiresIn() + System.currentTimeMillis()/1000;
			setBearerToken(token);
			setTokenExpiresAt(expiresAt);
    	} catch (Exception e) {
    		throw new NodeProcessException(e);
    	}

	}
    
}
