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

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.AnonymousAWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
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
import com.amazonaws.services.cognitoidp.model.AuthFlowType;
import com.amazonaws.services.cognitoidp.model.ChallengeNameType;
import com.amazonaws.services.cognitoidp.model.InitiateAuthRequest;
import com.amazonaws.services.cognitoidp.model.InitiateAuthResult;

public class CreateCognitoUser {
	
	private String POOL_ID;
	private String CLIENTAPP_ID;
	private String FED_POOL_ID;
	private String CUSTOMDOMAIN;
	private String REGION;
	
	public CreateCognitoUser() {
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
	
	private void createCognitoUser() {
//		AuthenticationHelper helper = new AuthenticationHelper(POOL_ID, CLIENTAPP_ID, "");
//		String token = helper.PerformSRPAuthentication("sophas-user-4", "password4321");
//		System.out.println("token: " + token);
		
		AWSCognitoIdentityProvider cognitoIdentityProvider = AWSCognitoIdentityProviderClientBuilder
				.standard()
				.withCredentials(new DefaultAWSCredentialsProviderChain())
				.withRegion(REGION)
				.build();
		
		AdminCreateUserRequest createUserRequest = new AdminCreateUserRequest();
		createUserRequest.setUsername("sophas-user-5");
		createUserRequest.setTemporaryPassword("password4321");
		createUserRequest.setUserPoolId(POOL_ID);
		
		
		List<AttributeType> list = new ArrayList<>();
		
		AttributeType attributeType1 = new AttributeType();
		attributeType1.setName("email");
		attributeType1.setValue("sophas-user-5@mailinator.com");
		list.add(attributeType1);
		
		createUserRequest.setUserAttributes(list);
		
		try {
			AdminCreateUserResult result = cognitoIdentityProvider.adminCreateUser(createUserRequest);
			System.out.println(result);
		} catch (Exception e) {
			System.out.println(e);
			return;
		}
		
		// Now update it
		AdminUpdateUserAttributesRequest updateRequest = new AdminUpdateUserAttributesRequest();
		updateRequest.setUsername("sophas-user-5");
		updateRequest.setUserPoolId(POOL_ID);
		
		list = new ArrayList<>();
		AttributeType custAttribute = new AttributeType();
		custAttribute.setName("custom:FORM_ID");
		custAttribute.setValue("6396");
		list.add(custAttribute);
		
		updateRequest.setUserAttributes(list);
		
		try {
			AdminUpdateUserAttributesResult updResult = cognitoIdentityProvider.adminUpdateUserAttributes(updateRequest);
			System.out.println("Update result: " + updResult);
		}
		catch (Exception e) {
			System.out.println("Exception while updating:" + e);
		}
		
		// Update auth challenge
		AdminInitiateAuthRequest adminInitiateAuthRequest = new AdminInitiateAuthRequest();
		adminInitiateAuthRequest.setAuthFlow(ADMIN_NO_SRP_AUTH);
		adminInitiateAuthRequest.setClientId(CLIENTAPP_ID);
		adminInitiateAuthRequest.setUserPoolId(POOL_ID);
		adminInitiateAuthRequest.addAuthParametersEntry("USERNAME", "sophas-user-5");
		adminInitiateAuthRequest.addAuthParametersEntry("PASSWORD", "password4321");
		
		AdminInitiateAuthResult initiateAuthResult = cognitoIdentityProvider.adminInitiateAuth(adminInitiateAuthRequest);
		System.out.println("challenge name=" + initiateAuthResult.getChallengeName());
		if (initiateAuthResult.getChallengeName().equals(NEW_PASSWORD_REQUIRED.toString())) {
			
			AdminRespondToAuthChallengeRequest authChallengeRequest = new AdminRespondToAuthChallengeRequest();
			authChallengeRequest.setChallengeName(NEW_PASSWORD_REQUIRED);
			authChallengeRequest.setUserPoolId(POOL_ID);
			authChallengeRequest.setClientId(CLIENTAPP_ID);
			authChallengeRequest.setSession(initiateAuthResult.getSession());
			Map<String, String> challResponses = new HashMap<>();
			challResponses.put("USERNAME", "sophas-user-5");
			challResponses.put("NEW_PASSWORD", "password4321");
			authChallengeRequest.setChallengeResponses(challResponses);
			
			AdminRespondToAuthChallengeResult authChallengeResult = cognitoIdentityProvider.adminRespondToAuthChallenge(authChallengeRequest);
			System.out.println("Auth challenge response: " + authChallengeResult);
		}
	}
	
	public static void main(String[] args) {
		
		CreateCognitoUser createCognitoUser = new CreateCognitoUser();
		
		createCognitoUser.createCognitoUser();
		
	}
}
