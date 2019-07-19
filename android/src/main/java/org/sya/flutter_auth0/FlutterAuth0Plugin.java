package org.sya.flutter_auth0;

import android.content.Intent;
import android.app.Activity;
import android.support.annotation.NonNull;
import android.support.customtabs.CustomTabsIntent;
import android.net.Uri;
import android.util.Base64;

import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;
import io.flutter.plugin.common.PluginRegistry.Registrar;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

/** FlutterAuth0Plugin */
public class FlutterAuth0Plugin implements MethodCallHandler {
  /** Plugin registration. */
  private Registrar registrar;
  private Result callbackResult;

  private static final String US_ASCII = "US-ASCII";
  private static final String SHA_256 = "SHA-256";
  private static final int CANCEL_EVENT_DELAY = 100;

  private FlutterAuth0Plugin(Registrar registrar) {
    this.registrar = registrar;
  }

  public static void registerWith(Registrar registrar) {
    final MethodChannel channel = new MethodChannel(registrar.messenger(), "org.sya/flutter_auth0");
    channel.setMethodCallHandler(new FlutterAuth0Plugin(registrar));
  }

  @Override
  public void onMethodCall(MethodCall call, Result result) {
      switch (call.method) {
          case "openUrl":
              openUrl(call, result);
              break;
          case "bundleIdentifier":
              handleBundleIdentifier(call, result);
              break;
          case "parameters":
              handleParameters(call, result);
              break;
          default:
              result.notImplemented();
      }
  }

  @SuppressWarnings("unchecked")
  private void handleBundleIdentifier(MethodCall call, Result result) {
    result.success(registrar.context().getPackageName());
  }

  private void openUrl(MethodCall call, Result result) {
    callbackResult = result;
    @SuppressWarnings("unchecked")
    Map<String, Object> arguments = (Map<String, Object>) call.arguments;
    final String url = (String) arguments.get("url");
    final Activity activity = this.registrar.activity();
    if (activity != null) {
      CustomTabsIntent.Builder builder = new CustomTabsIntent.Builder();
      CustomTabsIntent customTabsIntent = builder.build();
      customTabsIntent.launchUrl(activity, Uri.parse(url));
    } else {
      final Intent intent = new Intent(Intent.ACTION_VIEW);
      intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
      intent.setData(Uri.parse(url));
      this.registrar.context().startActivity(intent);
    }
  }

  private void handleParameters(MethodCall callback, Result result) {
    final String verifier = this.generateRandomValue();
    Map<String, Object> parameters = new HashMap<>();
    parameters.put("verifier", verifier);
    parameters.put("code_challenge", this.generateCodeChallenge(verifier));
    parameters.put("code_challenge_method", "S256");
    parameters.put("state", this.generateRandomValue());
    result.success(parameters);
  }

  private String generateRandomValue() {
    SecureRandom sr = new SecureRandom();
    byte[] code = new byte[32];
    sr.nextBytes(code);
    return this.getBase64String(code);
  }

  private String getBase64String(byte[] source) {
    return Base64.encodeToString(source, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
  }

  private byte[] getASCIIBytes(String value) {
    byte[] input;
    try {
        input = value.getBytes(US_ASCII);
    } catch (UnsupportedEncodingException e) {
        throw new IllegalStateException("Could not convert string to an ASCII byte array", e);
    }
    return input;
  }

  private byte[] getSHA256(byte[] input) {
    byte[] signature;
    try {
        MessageDigest md = MessageDigest.getInstance(SHA_256);
        md.update(input, 0, input.length);
        signature = md.digest();
    } catch (NoSuchAlgorithmException e) {
        throw new IllegalStateException("Failed to get SHA-256 signature", e);
    }
    return signature;
  }

  private String generateCodeChallenge(@NonNull String codeVerifier) {
      byte[] input = getASCIIBytes(codeVerifier);
      byte[] signature = getSHA256(input);
      return getBase64String(signature);
  }
}