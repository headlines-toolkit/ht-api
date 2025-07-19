import 'package:dart_frog/dart_frog.dart';
import 'package:ht_api/src/services/auth_service.dart';
import 'package:ht_shared/ht_shared.dart';

/// Middleware to handle authentication by verifying Bearer tokens.
///
/// It extracts the token from the 'Authorization' header, validates it using
/// the [AuthTokenService], and provides the resulting [User] object (or null)
/// into the request context via `context.read<User?>()`.
///
/// If a route requires authentication (determined by where this middleware is
/// applied) and the token is missing or invalid, it should ideally throw an
/// [UnauthorizedException] to be caught by the errorHandler.
///
/// **Usage:** Apply this middleware to routes or groups of routes that require
/// access to the authenticated user's identity or need protection.
Middleware authenticationProvider() {
  return (handler) {
    return (context) async {
      print('[AuthMiddleware] Entered.');
      // Read the AuthService to handle token validation and user data checks.
      AuthService authService;
      try {
        print('[AuthMiddleware] Attempting to read AuthService...');
        authService = context.read<AuthService>();
        print('[AuthMiddleware] Successfully read AuthService.');
      } catch (e, s) {
        print('[AuthMiddleware] FAILED to read AuthService: $e\n$s');
        rethrow;
      }
      User? user;

      // Extract the Authorization header
      print('[AuthMiddleware] Attempting to read Authorization header...');
      final authHeader = context.request.headers['Authorization'];
      print('[AuthMiddleware] Authorization header value: $authHeader');

      if (authHeader != null && authHeader.startsWith('Bearer ')) {
        final token = authHeader.substring(7); // Length of 'Bearer '
        print('[AuthMiddleware] Extracted Bearer token.');
        try {
          print('[AuthMiddleware] Attempting to get user from token...');
          // Use the AuthService to validate the token and ensure user data exists.
          user = await authService.getUserFromToken(token);
          print(
            '[AuthMiddleware] getUserFromToken returned: ${user?.id ?? 'null'}',
          );
          if (user != null) {
            print(
              '[AuthMiddleware] Authentication successful for user: ${user.id}',
            );
          } else {
            print(
              '[AuthMiddleware] Invalid token provided (getUserFromToken returned null).',
            );
          }
        } on HtHttpException catch (e) {
          print('Token validation failed: $e');
          user = null;
        } catch (e, s) {
          print(
            '[AuthMiddleware] Unexpected error during token validation: $e\n$s',
          );
          user = null;
        }
      } else {
        print('[AuthMiddleware] No valid Bearer token found in header.');
      }

      // Provide the User object (or null) into the context
      print(
        '[AuthMiddleware] Providing User (${user?.id ?? 'null'}) to context.',
      );
      return handler(context.provide<User?>(() => user));
    };
  };
}

/// Middleware factory that ensures a valid authenticated user exists.
///
/// Use this for routes that *strictly require* a logged-in user.
/// It reads the `User?` provided by `authenticationProvider` and throws
/// [UnauthorizedException] if the user is null.
Middleware requireAuthentication() {
  return (handler) {
    return (context) {
      final user = context.read<User?>();
      if (user == null) {
        print(
          'Authentication required but no valid user found. Denying access.',
        );
        // Throwing allows the central errorHandler to create the 401 response.
        throw const UnauthorizedException('Authentication required.');
      }
      // If user exists, proceed to the handler
      print('Authentication check passed for user: ${user.id}');
      return handler(context.provide<User>(() => user));
    };
  };
}
