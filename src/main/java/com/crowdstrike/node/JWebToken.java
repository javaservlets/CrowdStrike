package com.crowdstrike.node;
//import com.google.api.client.json.webtoken.JsonWebToken;
//import netscape.javascript.JSObject;
//import org.forgerock.json.JsonValue;
//import org.forgerock.json.jose.jwt.Jwt;
//import org.forgerock.json.jose.jwt.JwtClaimsSet;
//import org.forgerock.json.jose.jwt.JwtHeader;

import org.json.JSONException;
import org.json.JSONObject;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class JWebToken {
    private JSONObject payload=new JSONObject();
    private String passed;

    public JWebToken(String passed) {
        this.passed=passed;
    }

    public int getOverallScore() throws NoSuchAlgorithmException, JSONException {
        return JWebToken(passed);
    }

    public int JWebToken(String token) throws NoSuchAlgorithmException, JSONException {
        int score = 0;
        String[] parts=token.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid Token format");
        }

        payload=new JSONObject(decode(parts[1]));

        if (!payload.has("assessment")) {
            throw new JSONException("Payload doesn't contain overall score " + payload);
        } else {
            JSONObject assessment=payload.getJSONObject("assessment");
            String overall=assessment.getString("overall");
            score = Integer.parseInt(overall);
            //System.out.println(score);
        }
        return score;
    }

    private static String decode(String encodedString) {
        return new String(Base64.getUrlDecoder().decode(encodedString));
    }

}


