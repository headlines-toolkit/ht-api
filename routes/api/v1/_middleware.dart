import 'dart:io' show Platform; // To read environment variables

import 'package:dart_frog/dart_frog.dart';
import 'package:ht_api/src/middlewares/authentication_middleware.dart';
import 'package:ht_api/src/middlewares/error_handler.dart';
import 'package:logging/logging.dart';
import 'package:shelf_cors_headers/shelf_cors_headers.dart' as shelf_cors;

final _log = Logger('ApiV1Middleware');

/// Checks if the request's origin is allowed based on the environment.
///
/// In production (when `CORS_ALLOWED_ORIGIN` is set), it performs a strict
/// check against the specified origin.
/// In development, it dynamically allows any `localhost` or `127.0.0.1`
/// origin to support the Flutter web dev server's random ports.
bool _isOriginAllowed(String origin) {
  _log.info('[CORS] Checking origin: "$origin"');
  final allowedOriginEnv = Platform.environment['CORS_ALLOWED_ORIGIN'];

  if (allowedOriginEnv != null && allowedOriginEnv.isNotEmpty) {
    // Production: strict check against the environment variable.
    final isAllowed = origin == allowedOriginEnv;
    _log.info(
      '[CORS] Production check result: ${isAllowed ? 'ALLOWED' : 'DENIED'}',
    );
    return isAllowed;
  } else {
    // Development: dynamically allow any localhost origin.
    final isAllowed =
        origin.startsWith('http://localhost:') ||
        origin.startsWith('http://127.0.0.1:');
    _log.info(
      '[CORS] Development check result: ${isAllowed ? 'ALLOWED' : 'DENIED'}',
    );
    return isAllowed;
  }
}

Handler middleware(Handler handler) {
  // This middleware applies CORS and authentication to all routes under
  // `/api/v1/`. The order of `.use()` is important: the last one in the
  // chain runs first.
  return handler
      .use((handler) {
        // This is a custom middleware to wrap the auth provider with logging.
        final authMiddleware = authenticationProvider();
        final authHandler = authMiddleware(handler);

        return (context) {
          _log.info('[REQ_LIFECYCLE] Entering authentication middleware...');
          return authHandler(context);
        };
      })
      .use((handler) {
        // This is a custom middleware to wrap the CORS provider with logging.
        final corsMiddleware = fromShelfMiddleware(
          shelf_cors.corsHeaders(
            originChecker: _isOriginAllowed,
            headers: {
              shelf_cors.ACCESS_CONTROL_ALLOW_CREDENTIALS: 'true',
              shelf_cors.ACCESS_CONTROL_ALLOW_METHODS:
                  'GET, POST, PUT, DELETE, OPTIONS',
              shelf_cors.ACCESS_CONTROL_ALLOW_HEADERS:
                  'Origin, Content-Type, Authorization, Accept',
              shelf_cors.ACCESS_CONTROL_MAX_AGE: '86400',
            },
          ),
        );

        // The errorHandler is now also part of this scope.
        final errorHandlerMiddleware = errorHandler();

        return (context) {
          _log.info('[REQ_LIFECYCLE] Entering CORS and Error Handling scope...');
          // By wrapping the errorHandlerMiddleware inside the corsMiddleware,
          // we ensure that any response, including errors caught by the
          // handler, will have CORS headers applied.
          return corsMiddleware(errorHandlerMiddleware(handler))(context);
        };
      });
}
