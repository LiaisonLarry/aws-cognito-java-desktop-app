package com.amazonaws.sample.cognitoui;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.AnonymousAWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.AdminCreateUserRequest;
import com.amazonaws.services.cognitoidp.model.AdminCreateUserResult;
import com.amazonaws.services.cognitoidp.model.AttributeType;

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
				.withCredentials(new AWSStaticCredentialsProvider(new BasicAWSCredentials("AKIAIVJ6JL2AQDN5IJ6A",
						"dSGwWmIPDobaG7POQNYzYKrGaQoxhbSO7i0zh0ey")))
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
		}
	}
	
	public static void main(String[] args) {
		
		CreateCognitoUser createCognitoUser = new CreateCognitoUser();
		
		createCognitoUser.createCognitoUser();
		
	}
}
