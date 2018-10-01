package com.iws.forgerock;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.UUID;

import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.junit.Test;

import com.iwsinc.usermanager.client.OauthBearerToken;

public class TokenServiceTest
{
	int sleepSeconds = 2;
	
	OauthBearerToken getTestToken()
	{
		UUID guid = UUID.randomUUID();
		OauthBearerToken token = new OauthBearerToken();
		token.setAccessToken(guid.toString());
		token.setExpiresIn(sleepSeconds);
		token.setScope("ignored");
		token.setTokenType("client_credentials");
		
		return token;
	}
	
	// Singleton TokenService tests in one test case
	@Test
	public void testTokenServiceGetTokenAndExpiredToken() throws NodeProcessException, InterruptedException
	{
		
		OauthBearerToken testToken = getTestToken();
		
		TokenService tokenService = TokenService.getInstance();
		OauthService oauthService = mock(OauthService.class);
		TokenService.setOauthService(oauthService);

		// short-lived token will expire, then new one will be retrieved
		when(oauthService.getOauthToken()).thenReturn(testToken).thenReturn(testToken);
		
		assertEquals("tokens not equal", tokenService.getBearerToken(), testToken);
		assertFalse(tokenService.isTokenExpired());
		// wait for first to timeout
		Thread.sleep(sleepSeconds * 1000);
		assertTrue(tokenService.isTokenExpired());
		assertEquals("tokens not equal", tokenService.getBearerToken(), testToken);
		assertFalse(tokenService.isTokenExpired());
		
	}
	
}
