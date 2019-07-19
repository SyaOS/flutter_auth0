part of flutter_auth0;

class Auth0 {
  final String clientId;
  final String domain;

  Auth0({this.clientId, this.domain}) : assert(clientId != null),
    assert(domain != null);

  /*
   * Performs Auth with user credentials using the Password Realm Grant
   *
   * @param {Object} parameters password realm parameters
   * @param {String} parameters.username user's username or email
   * @param {String} parameters.password user's password
   * @param {String} parameters.realm name of the Realm where to Auth (or connection name)
   * @param {String} [parameters.audience] identifier of Resource Server (RS) to be included as audience (aud claim) of the issued access token
   * @param {String} [parameters.scope] scopes requested for the issued tokens. e.g. `openid profile`
   * @returns {Promise}
   * @see https://auth0.com/docs/api-auth/grant/password#realm-support
   *
   * @memberof Auth
  */
  Future<Auth0Token> passwordRealm({
    @required String username,
    @required String password,
    @required String realm,
    String audience,
    String scope = 'openid email profile token id id_token offline_access',
  }) async {
    http.Response response = await http.post(
      Uri.encodeFull(Auth0Meta.passwordRealm(domain)),
      headers: Auth0Meta.headers,
      body: jsonEncode(
        {
          'grant_type': 'http://auth0.com/oauth/grant-type/password-realm',
          'realm': realm,
          'username': username,
          'password': password,
          'audience': audience,
          'scope': scope,
          'client_id': clientId,
        },
      ),
    );
    Map<String, dynamic> tokenMap = await jsonDecode(response.body);
    if (response.statusCode == 200) {
      return Auth0Token.fromMap(tokenMap);
    } else {
      throw tokenMap['error_description'];
    }
  }

  Future<dynamic> refreshToken({
    @required String refreshToken,
  }) async {
    try {
      http.Response response = await http.post(
        Uri.encodeFull(Auth0Meta.refreshToken(domain)),
        body: jsonEncode(
          {
            'client_id': clientId,
            'refresh_token': refreshToken,
            'grant_type': 'refresh_token'
          }
        )
      );
      return jsonDecode(response.body);
    } catch (e) {
      throw Exception('auth0 refresh request error: ${e.message}');
    }
  }

  Future<dynamic> getUserInfo({
    @required String token,
  }) async {
    List<String> claims = [
      'sub',
      'name',
      'given_name',
      'family_name',
      'middle_name',
      'nickname',
      'preferred_username',
      'profile',
      'picture',
      'website',
      'email',
      'email_verified',
      'gender',
      'birthdate',
      'zoneinfo',
      'locale',
      'phone_number',
      'phone_number_verified',
      'address',
      'updated_at'
    ];
    Map<String, String> header = {'Authorization': 'Bearer $token'};
    header.addAll(Auth0Meta.headers);
    dynamic response = await http.get(
      Uri.encodeFull(Auth0Meta.infoUser(domain)),
      headers: header,
    );
    try {
      Map<dynamic, dynamic> userInfo = Map();
      dynamic body = json.decode(response.body);
      claims.forEach((claim) {
        userInfo[claim] = body[claim];
      });
      return userInfo;
    } catch (e) {
      return null;
    }
  }

  Future<dynamic> resetPassword({
    @required String email,
    @required String connection,
  }) async {
    http.Response response = await http.post(
        Uri.encodeFull(Auth0Meta.changePassword(domain)),
        headers: Auth0Meta.headers,
        body: jsonEncode({
          'client_id': clientId,
          'email': email,
          'connection': connection
        }
      )
    );
    dynamic _body = response.statusCode == 200 ? response.body : json.decode(response.body);
    if (response.statusCode == 200) {
      return _body.contains('We\'ve just sent you an email to reset your password');
    } else {
      throw Exception('reset password error: ${_body.description || _body.text}');
    }
  }

  Future<String> delegate({
    @required String token,
    @required String api,
  }) async {
    try {
      dynamic response = await http.post(
        Uri.encodeFull(Auth0Meta.delegation(domain)),
        headers: Auth0Meta.headers,
        body: jsonEncode({
          'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
          'id_token': token,
          'scope': 'openid',
          'client_id': clientId,
          'api_type': api,
        })
      );
      Map<dynamic, dynamic> tokenJson = jsonDecode(response.body);
      return tokenJson['id_token'];
    } catch (e) {
      return '[Delegation Request Error]: ${e.message}';
    }
  }

  Future<dynamic> createUser({
    @required String email,
    @required String password,
    @required String connection,
    String username,
    String metadata,
    bool waitResponse = false,
  }) async {
    if (waitResponse) {
      http.Response response = await http.post(
        Uri.encodeFull(Auth0Meta.createUser(domain)),
        headers: Auth0Meta.headers,
        body: jsonEncode(
          {
            'client_id': clientId,
            'email': email,
            'password': password,
            'connection': connection,
            'username': username != null ? username : email.split('@')[0],
            'user_metadata': metadata,
          },
        ),
      );
      dynamic body = json.decode(response.body);
      if (response.statusCode == 200) {
        return body;
      } else {
        throw body['message'];
      }
    } else {
      return http.post(
        Uri.encodeFull(Auth0Meta.createUser(domain)),
        headers: Auth0Meta.headers,
        body: jsonEncode({
          'client_id': clientId,
          'email': email,
          'password': password,
          'connection': connection,
          'username': username != null ? username : email.split('@')[0],
          'user_metadata': metadata,
        }),
      );
    }
  }
}