import 'package:dart_frog/dart_frog.dart';
import 'package:ht_api/src/config/app_dependencies.dart';
import 'package:ht_api/src/middlewares/error_handler.dart';
import 'package:ht_api/src/models/request_id.dart';
import 'package:ht_api/src/rbac/permission_service.dart';
import 'package:ht_api/src/registry/model_registry.dart';
import 'package:ht_api/src/services/auth_service.dart';
import 'package:ht_api/src/services/auth_token_service.dart';
import 'package:ht_api/src/services/dashboard_summary_service.dart';
import 'package:ht_api/src/services/token_blacklist_service.dart';
import 'package:ht_api/src/services/user_preference_limit_service.dart';
import 'package:ht_api/src/services/verification_code_storage_service.dart';
import 'package:ht_data_repository/ht_data_repository.dart';
import 'package:ht_email_repository/ht_email_repository.dart';
import 'package:ht_shared/ht_shared.dart';
import 'package:logging/logging.dart';
import 'package:uuid/uuid.dart';

// --- Middleware Definition ---
final _log = Logger('RootMiddleware');

// A flag to ensure the logger is only configured once for the application's
// entire lifecycle.
bool _loggerConfigured = false;

Handler middleware(Handler handler) {
  // This is the root middleware for the entire API. It's responsible for
  // providing all shared dependencies to the request context.
  // The order of `.use()` calls is important: the last one in the chain
  // runs first.

  // This check ensures that the logger is configured only once.
  if (!_loggerConfigured) {
    Logger.root.level = Level.ALL;
    Logger.root.onRecord.listen((record) {
      // ignore: avoid_print
      print(
        '${record.level.name}: ${record.time}: ${record.loggerName}: '
        '${record.message}',
      );
    });
    _loggerConfigured = true;
  }

  return handler
      // --- Core Middleware ---
      // These run after all dependencies have been provided.
      .use(requestLogger())
      // --- Request ID Provider ---
      // This middleware provides a unique ID for each request for tracing.
      // It depends on the Uuid provider, so it must come after it.
      .use((innerHandler) {
        return (context) {
          _log.info(
            '[REQ_LIFECYCLE] Request received. Generating RequestId...',
          );
          final uuid = context.read<Uuid>();
          final requestId = RequestId(uuid.v4());
          _log.info('[REQ_LIFECYCLE] RequestId generated: ${requestId.id}');
          return innerHandler(context.provide<RequestId>(() => requestId));
        };
      })
      // --- Dependency Provider ---
      // This is the outermost middleware. It runs once per request, before any
      // other middleware. It's responsible for initializing and providing all
      // dependencies for the request.
      .use((handler) {
        return (context) async {
          // 1. Ensure all dependencies are initialized (idempotent).
          _log.info('Ensuring all application dependencies are initialized...');
          await AppDependencies.instance.init();
          _log.info('Dependencies are ready.');

          // 2. Provide all dependencies to the inner handler.
          final deps = AppDependencies.instance;
          return handler
              .use(provider<ModelRegistryMap>((_) => modelRegistry))
              .use(provider<Uuid>((_) => const Uuid()))
              .use(
                provider<HtDataRepository<Headline>>(
                  (_) => deps.headlineRepository,
                ),
              ) //
              .use(
                provider<HtDataRepository<Topic>>((_) => deps.topicRepository),
              )
              .use(
                provider<HtDataRepository<Source>>(
                  (_) => deps.sourceRepository,
                ),
              ) //
              .use(
                provider<HtDataRepository<Country>>(
                  (_) => deps.countryRepository,
                ),
              ) //
              .use(
                provider<HtDataRepository<User>>((_) => deps.userRepository),
              ) //
              .use(
                provider<HtDataRepository<UserAppSettings>>(
                  (_) => deps.userAppSettingsRepository,
                ),
              )
              .use(
                provider<HtDataRepository<UserContentPreferences>>(
                  (_) => deps.userContentPreferencesRepository,
                ),
              )
              .use(
                provider<HtDataRepository<RemoteConfig>>(
                  (_) => deps.remoteConfigRepository,
                ),
              )
              .use(provider<HtEmailRepository>((_) => deps.emailRepository))
              .use(
                provider<TokenBlacklistService>(
                  (_) => deps.tokenBlacklistService,
                ),
              )
              .use(provider<AuthTokenService>((_) => deps.authTokenService))
              .use(
                provider<VerificationCodeStorageService>(
                  (_) => deps.verificationCodeStorageService,
                ),
              )
              .use(provider<AuthService>((_) => deps.authService))
              .use(
                provider<DashboardSummaryService>(
                  (_) => deps.dashboardSummaryService,
                ),
              )
              .use(provider<PermissionService>((_) => deps.permissionService))
              .use(
                provider<UserPreferenceLimitService>(
                  (_) => deps.userPreferenceLimitService,
                ),
              )
              .call(context);
        };
      });
}
