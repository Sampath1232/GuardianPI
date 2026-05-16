/// Guardian Pi — Auth Service (Secure login with biometric support)
import 'package:dio/dio.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:local_auth/local_auth.dart';

class AuthService {
  final Dio _dio;
  final FlutterSecureStorage _storage;
  final LocalAuthentication _localAuth;

  AuthService({required String baseUrl})
      : _dio = Dio(BaseOptions(
          baseUrl: baseUrl,
          connectTimeout: const Duration(seconds: 10),
          receiveTimeout: const Duration(seconds: 10),
        )),
        _storage = const FlutterSecureStorage(),
        _localAuth = LocalAuthentication();

  /// Login with email/password and store JWT securely
  Future<bool> login(String email, String password) async {
    try {
      final response = await _dio.post('/api/v1/auth/login', data: {
        'email': email,
        'password': password,
      });
      if (response.statusCode == 200) {
        final data = response.data;
        await _storage.write(key: 'access_token', value: data['access_token']);
        await _storage.write(key: 'refresh_token', value: data['refresh_token']);
        return true;
      }
      return false;
    } catch (e) {
      return false;
    }
  }

  /// Check if biometric authentication is available
  Future<bool> canUseBiometrics() async {
    return await _localAuth.canCheckBiometrics;
  }

  /// Authenticate with biometrics (fingerprint/face)
  Future<bool> authenticateWithBiometrics() async {
    return await _localAuth.authenticate(
      localizedReason: 'Authenticate to access Guardian Pi',
      options: const AuthenticationOptions(
        stickyAuth: true,
        biometricOnly: true,
      ),
    );
  }

  /// Get stored access token
  Future<String?> getAccessToken() async {
    return await _storage.read(key: 'access_token');
  }

  /// Refresh the JWT access token
  Future<bool> refreshToken() async {
    final refreshToken = await _storage.read(key: 'refresh_token');
    if (refreshToken == null) return false;
    try {
      final response = await _dio.post('/api/v1/auth/refresh', data: {
        'refresh_token': refreshToken,
      });
      if (response.statusCode == 200) {
        await _storage.write(key: 'access_token', value: response.data['access_token']);
        return true;
      }
      return false;
    } catch (e) {
      return false;
    }
  }

  /// Secure logout — clear all tokens
  Future<void> logout() async {
    await _storage.deleteAll();
  }
}

/// Riverpod provider for auth service
final authServiceProvider = Provider<AuthService>((ref) {
  return AuthService(baseUrl: 'https://api.guardianpi.io');
});
