part of flutter_auth0;

class WebAuth extends Auth0 {
  final String clientId;
  final String domain;
  static final String platformName = Platform.isAndroid ? 'android' : 'ios';
  static const MethodChannel _channel =
      const MethodChannel('org.sya/flutter_auth0');

  WebAuth({this.clientId, this.domain}) : assert(clientId != null),
    assert(domain != null),
    super(clientId: clientId, domain: domain);

  Future<dynamic> authorize({
    String state,
    String nonce,
    dynamic audience,
    dynamic scope,
    String connection,
    String connectionScope,
    String accessType,
    String prompt,
  }) {
    return _channel.invokeMethod('parameters', {}).then((dynamic params) async {
      try {
        String verifier = params['verifier'];
        String codeChallenge = params['code_challenge'];
        String codeChallengeMethod = params['code_challenge_method'];
        String _state = params['state'];
        dynamic bundleIdentifier =
          await _channel.invokeMethod('bundleIdentifier');
        String redirectUri =
          '$bundleIdentifier://${this.domain}/$platformName/$bundleIdentifier/callback';
        String expectedState = state != null ? state : _state;
        Map<String, dynamic> requestParams = <String, dynamic>{
          'client_id': clientId,
          'redirect_uri': redirectUri,
          'response_type': 'code',
          'state': expectedState,
          'audience': audience,
          'scope': scope,
          'connection': connection,
          'connection_scope': connectionScope,
          'access_type': accessType,
          'prompt': prompt,
          'code_challenge_method': codeChallengeMethod,
          'code_challenge': codeChallenge,
        };
        String authorizeUrl =
          'https://${this.domain}/authorize?${requestParams.keys.map((key) => "$key=${requestParams[key]}").toList().join("&")}';
        List<dynamic> response = await _channel
          .invokeMethod('openUrl', {'url': Uri.encodeFull(authorizeUrl)});
        // response like [error, redirectUrl]
        if (response[0] != null) {
          // do something with error
          throw Exception('auth0 error: ${response[0]}');
        }
        // parse redirectUrl
        String code = parseCallBackUri(response[1], expectedState);
        return exchange(
          code: code, refirectUri: redirectUri, verifier: verifier);
      } on PlatformException catch (e) {
        throw (e.message);
      }
    });
  }

  String parseCallBackUri(String url, String expectedState) {
    Uri uri = Uri.parse(url);
    if (uri.queryParameters['error'] != null) {
      throw Exception('auth0 response error: ${uri.queryParameters['error']}');
    }
    if (uri.queryParameters['state'] != expectedState) {
      throw Exception('auth0 response state is unexpected');
    }
    return uri.queryParameters['code'];
  }

  Future<dynamic> exchange({
    @required String code,
    @required String refirectUri,
    @required String verifier,
  }) async {
    try {
      http.Response response = await http.post(
        Uri.encodeFull(Auth0Meta.refreshToken(domain)),
        headers: Auth0Meta.headers,
        body: jsonEncode({
          'code': code,
          'code_verifier': verifier,
          'redirect_uri': refirectUri,
          'client_id': this.clientId,
          'grant_type': 'authorization_code'
        })
      );
      Map<dynamic, dynamic> json = jsonDecode(response.body);
      return {
        'access_token': json['access_token'],
        'refresh_token': json['refresh_token'],
        'id_token': json['id_token'],
        'token_type': json['token_type'],
        'expires_in': json['expires_in']
      };
    } catch (e) {
      return '[Exchange WebAuthentication Error]: ${e.message}';
    }
  }

  Future<void> clearSession({
    bool federated = false,
  }) async {
    if (platformName == 'ios') {
      try {
        dynamic bundleIdentifier =
            await _channel.invokeMethod('bundleIdentifier');
        String redirectUri =
            '$bundleIdentifier://${this.domain}/$platformName/$bundleIdentifier/callback';
        String logoutUrl = Uri.encodeFull(
            '${Auth0Meta.logout(domain)}?client_id=${this.clientId}&federated=$federated&returnTo=$redirectUri');
        await _channel.invokeMethod('showUrl', {'url': logoutUrl});
      } on PlatformException catch (e) {
        throw e.message;
      }
    }
  }
}