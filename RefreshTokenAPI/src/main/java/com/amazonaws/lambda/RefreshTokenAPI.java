package com.amazonaws.lambda;

import java.util.HashMap;
import java.util.Map;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.lambda.thirdparty.com.fasterxml.jackson.databind.ObjectMapper;
import com.amazonaws.lambda.thirdparty.com.google.gson.Gson;
import com.amazonaws.lambda.thirdparty.org.json.JSONObject;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthRequest;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthResult;
import com.amazonaws.services.cognitoidp.model.AuthFlowType;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;

public class RefreshTokenAPI implements RequestHandler<APIGatewayProxyRequest, APIGatewayProxyResponse> {

	private String AccessKey = "AKIAYUCMZEDM5Q3UW7ZH";
	private String SecretKey = "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";

	private String AppClientId = "6t097jurf8m5rhj6gh2cklmik8";
	private String userPool = "ap-south-1_xZ7yl7rZn";

	APIGatewayProxyResponse response = new APIGatewayProxyResponse();

	@Override
	public APIGatewayProxyResponse handleRequest(APIGatewayProxyRequest input, Context context) {
		context.getLogger().log("Input: " + input);

		try {

			String body = input.getBody();
			ObjectMapper mapper = new ObjectMapper();
			Map<String, String> map = mapper.readValue(body, Map.class);
			String RefreshToken = map.get("refreshToken");

			if(RefreshToken != null && RefreshToken.isEmpty() == false) {
				Map<String, String> authParams = new HashMap<String, String>();
				authParams.put("REFRESH_TOKEN", RefreshToken);

				AWSCredentials cred = new BasicAWSCredentials(AccessKey, SecretKey);
				AWSCredentialsProvider credProvider = new AWSStaticCredentialsProvider(cred);
				AWSCognitoIdentityProvider client = AWSCognitoIdentityProviderClientBuilder.standard()
						.withCredentials(credProvider).withRegion(Regions.AP_SOUTH_1).build();
				context.getLogger().log("Cognito Client created !");
				
			

				AdminInitiateAuthRequest refresh = new AdminInitiateAuthRequest().withAuthFlow(AuthFlowType.REFRESH_TOKEN)
						.withUserPoolId(userPool).withClientId(AppClientId).withAuthParameters(authParams);
				context.getLogger().log("Auth request created !");
				
				AdminInitiateAuthResult tokens = client.adminInitiateAuth(refresh);
				context.getLogger().log("Auth result generated !");
				JSONObject obj = new JSONObject(tokens.toString());
				obj.remove("ChallengeParameters");
				
				JSONObject auth = obj.getJSONObject("AuthenticationResult");
				auth.put("idToken", auth.get("IdToken"));
				auth.remove("IdToken");
				
				auth.put("expiresIn", auth.get("ExpiresIn"));
				auth.remove("ExpiresIn");
				
				auth.put("tokenType", auth.get("TokenType"));
				auth.remove("TokenType");
				
				auth.put("accessToken", auth.get("AccessToken"));
				auth.remove("AccessToken");
				
				auth.put("refreshToken", RefreshToken);
				 
				response.setBody(obj.toString());
				response.setStatusCode(200);
				return response;
			}else {
				
				context.getLogger().log("refresh token not found !"); 
				response.setBody("Please insert a refresh Token ");
				response.setStatusCode(200);
				return response;
				
			}

		} catch (Exception e) {
			
			context.getLogger().log("Exception occured : -" + e.getMessage()); 
			response.setBody("Exception occured : -" + e.getMessage());
			response.setStatusCode(400);
			return response;

		}


	}

}
