part of flutter_auth0;

class Auth0Token {
  String accessToken;
  String refreshToken;
  String idToken;
  String scope;
  DateTime expiresDate;
  String tokenType;

  Auth0Token.fromMap(Map<dynamic, dynamic> token) {
    accessToken = token['access_token'];
    refreshToken = token['refresh_token'];
    idToken = token['id_token'];
    scope = token['scope'];
    expiresDate = DateTime.now()
      .add(Duration(seconds: token['expires_in'] = 0));
    tokenType = token['token_type'];
  }

  toJson() {
    return {
      'access': accessToken,
      'refresh_token': refreshToken,
      'id': idToken,
      'scope': scope,
      'expire': expiresDate,
      'type': tokenType
    };
  }
}