package com.amazonaws.sample.cognitoui;

import static com.amazonaws.services.cognitoidp.model.AuthFlowType.ADMIN_NO_SRP_AUTH;
import static com.amazonaws.services.cognitoidp.model.ChallengeNameType.NEW_PASSWORD_REQUIRED;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.AdminCreateUserRequest;
import com.amazonaws.services.cognitoidp.model.AdminCreateUserResult;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthRequest;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthResult;
import com.amazonaws.services.cognitoidp.model.AdminRespondToAuthChallengeRequest;
import com.amazonaws.services.cognitoidp.model.AdminRespondToAuthChallengeResult;
import com.amazonaws.services.cognitoidp.model.AdminUpdateUserAttributesRequest;
import com.amazonaws.services.cognitoidp.model.AdminUpdateUserAttributesResult;
import com.amazonaws.services.cognitoidp.model.AttributeType;
import com.amazonaws.services.cognitoidp.model.InitiateAuthRequest;
import com.amazonaws.services.cognitoidp.model.InitiateAuthResult;

public class GetToken {
	
	private String POOL_ID;
	private String CLIENTAPP_ID;
	private String FED_POOL_ID;
	private String CUSTOMDOMAIN;
	private String REGION;
	
	public GetToken() {
		Properties prop = new Properties();
		InputStream input = null;
		
		try {
			input = getClass().getClassLoader().getResourceAsStream("config.properties");
			
			// load a properties file
			prop.load(input);
			
			// Read the property values
			POOL_ID = prop.getProperty("POOL_ID");
			CLIENTAPP_ID = prop.getProperty("CLIENTAPP_ID");
			FED_POOL_ID = prop.getProperty("FED_POOL_ID");
			CUSTOMDOMAIN = prop.getProperty("CUSTOMDOMAIN");
			REGION = prop.getProperty("REGION");
			
		} catch (IOException ex) {
			ex.printStackTrace();
		} finally {
			if (input != null) {
				try {
					input.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	private void getAuthToken() {
		
		AWSCognitoIdentityProvider cognitoIdentityProvider = AWSCognitoIdentityProviderClientBuilder
				.standard()
				.withCredentials(new DefaultAWSCredentialsProviderChain())
				.build();
		
		Map<String, String> authParameters = new HashMap<>();
		authParameters.put("USERNAME", "sophas-user-3");
		authParameters.put("PASSWORD", "password4321");
		
		InitiateAuthRequest initiateAuthRequest = new InitiateAuthRequest();
		initiateAuthRequest.setAuthFlow("USER_PASSWORD_AUTH");
		initiateAuthRequest.setClientId(CLIENTAPP_ID);
		initiateAuthRequest.setAuthParameters(authParameters);

		InitiateAuthResult result = cognitoIdentityProvider.initiateAuth(initiateAuthRequest);
		String authToken = result.getAuthenticationResult().getAccessToken();
		System.out.println("Auth token: " + authToken);
	}
	
	public static void main(String[] args) {
		
		GetToken createCognitoUser = new GetToken();
		
		createCognitoUser.getAuthToken();
		
	}
}
