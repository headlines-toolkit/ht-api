import 'package:ht_api/src/rbac/permission_service.dart';
import 'package:ht_api/src/rbac/permissions.dart';
import 'package:ht_api/src/services/auth_token_service.dart';
import 'package:ht_api/src/services/verification_code_storage_service.dart';
import 'package:ht_data_repository/ht_data_repository.dart';
import 'package:ht_email_repository/ht_email_repository.dart';
import 'package:ht_shared/ht_shared.dart';
import 'package:logging/logging.dart';
import 'package:uuid/uuid.dart';

/// {@template auth_service}
/// Service responsible for orchestrating authentication logic on the backend.
///
/// It coordinates interactions between user data storage, token generation,
/// verification code management, and email sending.
/// {@endtemplate}
class AuthService {
  /// {@macro auth_service}
  const AuthService({
    required HtDataRepository<User> userRepository,
    required AuthTokenService authTokenService,
    required VerificationCodeStorageService verificationCodeStorageService,
    required HtEmailRepository emailRepository,
    required HtDataRepository<UserAppSettings> userAppSettingsRepository,
    required HtDataRepository<UserContentPreferences>
    userContentPreferencesRepository,
    required PermissionService permissionService,
    required Uuid uuidGenerator,
    required Logger log,
  }) : _userRepository = userRepository,
       _authTokenService = authTokenService,
       _verificationCodeStorageService = verificationCodeStorageService,
       _permissionService = permissionService,
       _emailRepository = emailRepository,
       _userAppSettingsRepository = userAppSettingsRepository,
       _userContentPreferencesRepository = userContentPreferencesRepository,
       _uuid = uuidGenerator,
       _log = log;

  final HtDataRepository<User> _userRepository;
  final AuthTokenService _authTokenService;
  final VerificationCodeStorageService _verificationCodeStorageService;
  final HtEmailRepository _emailRepository;
  final HtDataRepository<UserAppSettings> _userAppSettingsRepository;
  final HtDataRepository<UserContentPreferences>
  _userContentPreferencesRepository;
  final PermissionService _permissionService;
  final Logger _log;
  final Uuid _uuid;

  // A simple in-memory lock to prevent race conditions during user data creation.
  final Set<String> _userCreationLocks = {};

  /// Validates a token, retrieves the user, and ensures user data exists.
  ///
  /// This method orchestrates the process of:
  /// 1. Validating the token using the [AuthTokenService].
  /// 2. If the user is found, calling [_ensureUserDataExists] to guarantee
  ///    that related documents like settings and preferences are present.
  ///
  /// This is the primary method that should be used by middleware to get a
  /// fully validated user object whose data integrity is confirmed.
  ///
  /// Returns the [User] if the token is valid and the user exists.
  /// Returns `null` if the token is invalid or the user is not found.
  /// Throws [HtHttpException] or its subtypes on failure.
  Future<User?> getUserFromToken(String token) async {
    final user = await _authTokenService.validateToken(token);

    if (user != null) {
      // Ensure that the essential user-specific documents (settings,
      // preferences) exist for the user, creating them with default values
      // if they are missing.
      await _ensureUserDataExists(user);
    }

    return user;
  }

  /// Initiates the email sign-in process.
  ///
  /// This method is context-aware based on the [isDashboardLogin] flag.
  ///
  /// - For the user-facing app (`isDashboardLogin: false`), it generates and
  ///   sends a verification code to the given [email] without pre-validation,
  ///   supporting a unified sign-in/sign-up flow.
  /// - For the dashboard (`isDashboardLogin: true`), it performs a strict
  ///   login-only check. It verifies that a user with the given [email] exists
  ///   and has either the 'admin' or 'publisher' role *before* sending a code.
  ///
  /// - [email]: The email address to send the code to.
  /// - [isDashboardLogin]: A flag to indicate if this is a login attempt from
  ///   the dashboard, which enforces stricter checks.
  ///
  /// Throws [UnauthorizedException] if `isDashboardLogin` is true and the user
  /// does not exist.
  /// Throws [ForbiddenException] if `isDashboardLogin` is true and the user
  /// exists but lacks the required roles.
  Future<void> initiateEmailSignIn(
    String email, {
    bool isDashboardLogin = false,
  }) async {
    try {
      // For dashboard login, first validate the user exists and has permissions.
      if (isDashboardLogin) {
        final user = await _findUserByEmail(email);

        // For dashboard login, the user must exist AND have permission.
        // If either condition fails, throw the appropriate exception.
        if (user == null) {
          _log.warning('Dashboard login failed: User $email not found.');
          throw const UnauthorizedException(
            'This email address is not registered for dashboard access.',
          );
        } else if (!_permissionService.hasPermission(
          user,
          Permissions.dashboardLogin,
        )) {
          _log.warning(
            'Dashboard login failed: User ${user.id} lacks required permission (${Permissions.dashboardLogin}).',
          );
          throw const ForbiddenException(
            'Your account does not have the required permissions to sign in.',
          );
        }

        _log.info('Dashboard user ${user.id} verified successfully.');
      }

      // Generate and store the code for standard sign-in
      final code = await _verificationCodeStorageService
          .generateAndStoreSignInCode(email);

      // Send the code via email
      await _emailRepository.sendOtpEmail(recipientEmail: email, otpCode: code);
      _log.info('Initiated email sign-in for $email, code sent.');
    } on HtHttpException {
      // Propagate known exceptions from dependencies or from this method's logic.
      // This ensures that specific errors like ForbiddenException are not
      // masked as a generic server error.
      rethrow;
    } catch (e, s) {
      // Catch unexpected errors during orchestration.
      _log.severe('Error during initiateEmailSignIn for $email: $e', e, s);
      throw const OperationFailedException(
        'Failed to initiate email sign-in process.',
      );
    }
  }

  /// Completes the email sign-in process by verifying the code.
  ///
  /// This method is context-aware based on the [isDashboardLogin] flag.
  ///
  /// - For the dashboard (`isDashboardLogin: true`), it validates the code and
  ///   logs in the existing user. It will not create a new user in this flow.
  /// - For the user-facing app (`isDashboardLogin: false`), it validates the
  ///   code and either logs in the existing user or creates a new one with a
  ///   'standardUser' role if they don't exist.
  ///
  /// Returns the authenticated [User] and a new authentication token.
  ///
  /// Throws [InvalidInputException] if the code is invalid or expired.
  Future<({User user, String token})> completeEmailSignIn(
    String email,
    String code, {
    // Flag to indicate if this is a login attempt from the dashboard,
    // which enforces stricter checks.
    bool isDashboardLogin = false,
  }) async {
    // 1. Validate the code for standard sign-in
    final isValidCode = await _verificationCodeStorageService
        .validateSignInCode(email, code);
    if (!isValidCode) {
      throw const InvalidInputException(
        'Invalid or expired verification code.',
      );
    }

    // After successful code validation, clear the sign-in code
    try {
      await _verificationCodeStorageService.clearSignInCode(email);
    } catch (e) {
      // Log or handle if clearing fails, but don't let it block sign-in
      _log.warning(
        'Warning: Failed to clear sign-in code for $email after validation: $e',
      );
    }

    // 2. Find or create the user based on the context
    User user;
    try {
      // Attempt to find user by email
      final existingUser = await _findUserByEmail(email);
      if (existingUser != null) {
        user = existingUser;
        // If this is a dashboard login, re-verify the user's dashboard role.
        // This closes the loophole where a non-admin user could request a code
        // via the app flow and then use it to log into the dashboard.
        if (isDashboardLogin) {
          if (user.email != email) {
            // This is a critical security check. If the user found by email
            // somehow has a different email than the one provided, it's a
            // sign of a serious issue (like the data layer bug we fixed).
            // We throw a generic error to avoid revealing information.
            _log.severe(
              'CRITICAL: Mismatch between requested email ($email) and found '
              'user email (${user.email}) during dashboard login for user '
              'ID ${user.id}.',
            );
            throw const UnauthorizedException('User account does not exist.');
          }
          if (!_permissionService.hasPermission(
            user,
            Permissions.dashboardLogin,
          )) {
            _log.warning(
              'Dashboard login failed: User ${user.id} lacks required '
              'permission during code verification.',
            );
            throw const ForbiddenException(
              'Your account does not have the required permissions to sign in.',
            );
          }
          _log.info('Dashboard user ${user.id} re-verified successfully.');
        }
      } else {
        // User not found.
        if (isDashboardLogin) {
          // This should not happen if the request-code flow is correct.
          // It's a safeguard.
          _log.severe(
            'Error: Dashboard login verification failed for non-existent user $email.',
          );
          throw const UnauthorizedException('User account does not exist.');
        }

        // Create a new user for the standard app flow.
        _log.info('User not found for $email, creating new user.');

        // All new users created via the public API get the standard role.
        // Admin users must be provisioned out-of-band (e.g., via fixtures).
        user = User(
          id: _uuid.v4(),
          email: email,
          appRole: AppUserRole.standardUser,
          dashboardRole: DashboardUserRole.none,
          createdAt: DateTime.now(),
          feedActionStatus: Map.fromEntries(
            FeedActionType.values.map(
              (type) => MapEntry(
                type,
                const UserFeedActionStatus(isCompleted: false),
              ),
            ),
          ),
        );
        user = await _userRepository.create(item: user);
        _log.info('Created new user: ${user.id} with appRole: ${user.appRole}');

        // Ensure default documents are created for the new user.
        await _ensureUserDataExists(user);
      }
    } on HtHttpException {
      // Propagate known exceptions from dependencies or from this method's logic.
      // This ensures that specific errors like ForbiddenException are not
      // masked as a generic server error.
      rethrow;
    } catch (e, s) {
      _log.severe(
        'Unexpected error during user lookup/creation for $email: $e',
        e,
        s,
      );
      throw const OperationFailedException('Failed to process user account.');
    }

    // 3. Generate authentication token
    try {
      final token = await _authTokenService.generateToken(user);
      _log.info('Generated token for user ${user.id}');
      return (user: user, token: token);
    } catch (e) {
      _log.severe('Error generating token for user ${user.id}: $e');
      throw const OperationFailedException(
        'Failed to generate authentication token.',
      );
    }
  }

  /// Performs anonymous sign-in.
  ///
  /// Creates a new anonymous user record and generates an auth token.
  /// Returns the anonymous User and the generated token.
  /// Throws [OperationFailedException] if user creation or token generation fails.
  Future<({User user, String token})> performAnonymousSignIn() async {
    // 1. Create anonymous user
    User user;
    try {
      user = User(
        id: _uuid.v4(),
        // Use a unique placeholder email for anonymous users to satisfy the
        // non-nullable email constraint.
        email: '${_uuid.v4()}@anonymous.com',
        appRole: AppUserRole.guestUser,
        dashboardRole: DashboardUserRole.none,
        createdAt: DateTime.now(),
        feedActionStatus: Map.fromEntries(
          FeedActionType.values.map(
            (type) =>
                MapEntry(type, const UserFeedActionStatus(isCompleted: false)),
          ),
        ),
      );
      user = await _userRepository.create(item: user);
      _log.info('Created anonymous user: ${user.id}');

      // Ensure default documents are created for the new anonymous user.
      await _ensureUserDataExists(user);
    } on HtHttpException catch (e) {
      _log.severe('Error creating anonymous user: $e');
      throw const OperationFailedException('Failed to create anonymous user.');
    } catch (e) {
      _log.severe('Unexpected error during anonymous user creation: $e');
      throw const OperationFailedException(
        'Failed to process anonymous sign-in.',
      );
    }

    // 2. Generate token
    try {
      final token = await _authTokenService.generateToken(user);
      _log.info('Generated token for anonymous user ${user.id}');
      return (user: user, token: token);
    } catch (e) {
      _log.severe('Error generating token for anonymous user ${user.id}: $e');
      throw const OperationFailedException(
        'Failed to generate authentication token.',
      );
    }
  }

  /// Performs server-side sign-out actions.
  ///
  /// Currently, this method logs the sign-out attempt. True server-side
  /// token invalidation (e.g., blacklisting a JWT) is not implemented
  /// in the underlying [AuthTokenService] and would require adding that
  /// capability (e.g., an `invalidateToken` method and a blacklist store).
  ///
  /// The primary client-side action (clearing the local token) is handled
  /// separately by the client application.
  ///
  /// Performs server-side sign-out actions, including token invalidation.
  ///
  /// Invalidates the provided authentication [token] using the
  /// [AuthTokenService].
  ///
  /// The primary client-side action (clearing the local token) is handled
  /// separately by the client application.
  ///
  /// Throws [OperationFailedException] if token invalidation fails.
  Future<void> performSignOut({
    required String userId,
    required String token,
  }) async {
    _log.info(
      'Received request for server-side sign-out actions '
      'for user $userId.',
    );

    try {
      // Invalidate the token using the AuthTokenService
      await _authTokenService.invalidateToken(token);
      _log.info('Token invalidation logic executed for user $userId.');
    } on HtHttpException catch (_) {
      // Propagate known exceptions from the token service
      rethrow;
    } catch (e) {
      // Catch unexpected errors during token invalidation
      _log.severe('Error during token invalidation for user $userId: $e');
      throw const OperationFailedException(
        'Failed server-side sign-out: Token invalidation failed.',
      );
    }

    _log.info('Server-side sign-out actions complete for user $userId.');
  }

  /// Initiates the process of linking an [emailToLink] to an existing
  /// authenticated [anonymousUser]'s account.
  ///
  /// Throws [ConflictException] if the [emailToLink] is already in use by
  /// another permanent account, or if the [anonymousUser] is not actually
  /// anonymous, or if the [emailToLink] is already pending verification for
  /// another linking process.
  /// Throws [OperationFailedException] for other errors.
  Future<void> initiateLinkEmailProcess({
    required User anonymousUser,
    required String emailToLink,
  }) async {
    if (anonymousUser.appRole != AppUserRole.guestUser) {
      throw const BadRequestException(
        'Account is already permanent. Cannot link email.',
      );
    }

    try {
      // 1. Check if emailToLink is already used by another permanent user.
      final existingUsersResponse = await _userRepository.readAll(
        filter: {'email': emailToLink},
      );

      // Filter for permanent users (not guests) that are not the current user.
      final conflictingPermanentUsers = existingUsersResponse.items.where(
        (u) => u.appRole != AppUserRole.guestUser && u.id != anonymousUser.id,
      );

      if (conflictingPermanentUsers.isNotEmpty) {
        throw ConflictException(
          'Email address "$emailToLink" is already in use by another account.',
        );
      }

      // 2. Generate and store the link code.
      // The storage service itself might throw ConflictException if emailToLink
      // is pending for another user or if this user has a pending code.
      final code = await _verificationCodeStorageService
          .generateAndStoreLinkCode(
            userId: anonymousUser.id,
            emailToLink: emailToLink,
          );

      // 3. Send the code via email
      await _emailRepository.sendOtpEmail(
        recipientEmail: emailToLink,
        otpCode: code,
      );
      _log.info(
        'Initiated email link for user ${anonymousUser.id} to email $emailToLink, code sent: $code .',
      );
    } on HtHttpException {
      rethrow;
    } catch (e) {
      _log.severe(
        'Error during initiateLinkEmailProcess for user ${anonymousUser.id}, email $emailToLink: $e',
      );
      throw OperationFailedException(
        'Failed to initiate email linking process: $e',
      );
    }
  }

  /// Completes the email linking process for an [anonymousUser] by verifying
  /// the [codeFromUser].
  ///
  /// If successful, updates the user to be permanent with the linked email
  /// and returns the updated User and a new authentication token.
  /// Throws [InvalidInputException] if the code is invalid or expired.
  /// Throws [OperationFailedException] for other errors.
  Future<({User user, String token})> completeLinkEmailProcess({
    required User anonymousUser,
    required String codeFromUser,
    required String oldAnonymousToken, // Needed to invalidate it
  }) async {
    if (anonymousUser.appRole != AppUserRole.guestUser) {
      // Should ideally not happen if flow is correct, but good safeguard.
      throw const BadRequestException(
        'Account is already permanent. Cannot complete email linking.',
      );
    }

    try {
      // 1. Validate the link code and retrieve the email that was being linked.
      final linkedEmail = await _verificationCodeStorageService
          .validateAndRetrieveLinkedEmail(
            userId: anonymousUser.id,
            linkCode: codeFromUser,
          );

      if (linkedEmail == null) {
        throw const InvalidInputException(
          'Invalid or expired verification code for email linking.',
        );
      }

      // 2. Update the user to be permanent.
      final updatedUser = anonymousUser.copyWith(
        email: linkedEmail,
        appRole: AppUserRole.standardUser,
      );
      final permanentUser = await _userRepository.update(
        id: updatedUser.id,
        item: updatedUser,
      );
      _log.info(
        'User ${permanentUser.id} successfully linked with email $linkedEmail.',
      );

      // Ensure user data exists after linking.
      await _ensureUserDataExists(permanentUser);

      // 3. Generate a new authentication token for the now-permanent user.
      final newToken = await _authTokenService.generateToken(permanentUser);
      _log.info('Generated new token for linked user ${permanentUser.id}');

      // 4. Invalidate the old anonymous token.
      try {
        await _authTokenService.invalidateToken(oldAnonymousToken);
        _log.info(
          'Successfully invalidated old anonymous token for user ${permanentUser.id}.',
        );
      } catch (e) {
        // Log error but don't fail the whole linking process if invalidation fails.
        // The new token is more important.
        _log.warning(
          'Warning: Failed to invalidate old anonymous token for user ${permanentUser.id}: $e',
        );
      }

      // 5. Clear the link code from storage.
      try {
        await _verificationCodeStorageService.clearLinkCode(anonymousUser.id);
      } catch (e) {
        _log.warning(
          'Warning: Failed to clear link code for user ${anonymousUser.id} after linking: $e',
        );
      }

      return (user: permanentUser, token: newToken);
    } on HtHttpException {
      rethrow;
    } catch (e) {
      _log.severe(
        'Error during completeLinkEmailProcess for user ${anonymousUser.id}: $e',
      );
      throw OperationFailedException(
        'Failed to complete email linking process: $e',
      );
    }
  }

  /// Deletes a user account and associated authentication data.
  ///
  /// This includes deleting the user record from the repository and clearing
  /// any pending verification codes.
  ///
  /// Throws [NotFoundException] if the user does not exist.
  /// Throws [OperationFailedException] for other errors during deletion or cleanup.
  Future<void> deleteAccount({required String userId}) async {
    try {
      // Fetch the user first to get their email if needed for cleanup
      final userToDelete = await _userRepository.read(id: userId);
      _log.info('Found user ${userToDelete.id} for deletion.');

      // 1. Explicitly delete associated user data. Unlike relational databases
      // with CASCADE constraints, MongoDB requires manual deletion of related
      // documents in different collections.
      await _userAppSettingsRepository.delete(id: userId, userId: userId);
      _log.info('Deleted UserAppSettings for user ${userToDelete.id}.');

      await _userContentPreferencesRepository.delete(
        id: userId,
        userId: userId,
      );
      _log.info('Deleted UserContentPreferences for user ${userToDelete.id}.');

      // 2. Delete the main user record. This also implicitly invalidates
      // tokens that rely on user lookup, as the user will no longer exist.
      await _userRepository.delete(id: userId);
      _log.info('User ${userToDelete.id} deleted from repository.');

      // 3. Clear any pending verification codes for this user ID (linking).
      try {
        await _verificationCodeStorageService.clearLinkCode(userId);
        _log.info('Cleared link code for user ${userToDelete.id}.');
      } catch (e) {
        // Log but don't fail deletion if clearing codes fails
        _log.warning(
          'Warning: Failed to clear link code for user ${userToDelete.id}: $e',
        );
      }

      // 4. Clear any pending sign-in codes for the user's email (if they had one).
      // The email for anonymous users is a placeholder and not used for sign-in.
      if (userToDelete.appRole != AppUserRole.guestUser) {
        try {
          await _verificationCodeStorageService.clearSignInCode(
            userToDelete.email,
          );
          _log.info('Cleared sign-in code for email ${userToDelete.email}.');
        } catch (e) {
          _log.warning(
            'Warning: Failed to clear sign-in code for email ${userToDelete.email}: $e',
          );
        }
      }

      _log.info('Account deletion process completed for user $userId.');
    } on NotFoundException {
      // Propagate NotFoundException if user doesn't exist
      rethrow;
    } on HtHttpException catch (_) {
      // Propagate other known exceptions from dependencies
      rethrow;
    } catch (e) {
      // Catch unexpected errors during orchestration
      _log.severe('Error during deleteAccount for user $userId: $e');
      throw OperationFailedException('Failed to delete user account: $e');
    }
  }

  /// Finds a user by their email address.
  ///
  /// Returns the [User] if found, otherwise `null`.
  /// Re-throws any [HtHttpException] from the repository.
  Future<User?> _findUserByEmail(String email) async {
    try {
      final response = await _userRepository.readAll(filter: {'email': email});
      if (response.items.isNotEmpty) {
        return response.items.first;
      }
      return null;
    } on HtHttpException {
      rethrow;
    }
  }

  /// Ensures that the essential user-specific documents (settings, preferences)
  /// exist for a given user, creating them with default values if they are missing.
  ///
  /// This method is crucial for maintaining data integrity, especially for users
  /// who might have been created before these documents were part of the standard
  /// user creation process. It is designed to be robust against race conditions.
  Future<void> _ensureUserDataExists(User user) async {
    // If a creation process for this user is already underway, wait briefly.
    // This prevents multiple requests from trying to create the same documents.
    while (_userCreationLocks.contains(user.id)) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }

    // First, perform a quick check without locking. If the data already exists,
    // we can exit early. This is an optimization for the common case where the
    // user is already fully set up.
    try {
      await _userAppSettingsRepository.read(id: user.id, userId: user.id);
      await _userContentPreferencesRepository.read(id: user.id, userId: user.id);
      return; // Both documents exist, nothing more to do.
    } on NotFoundException {
      // At least one document is missing. Proceed to the synchronized creation logic.
      _log.info(
        'User data check for ${user.id} found missing documents. '
        'Proceeding to creation lock.',
      );
    }

    // Acquire a lock to ensure only one request handles creation.
    _userCreationLocks.add(user.id);
    try {
      // --- Re-check and create within the lock ---
      // It's crucial to re-check inside the lock in case another request
      // created the documents while this one was waiting for the lock.

      // Check for UserAppSettings
      try {
        await _userAppSettingsRepository.read(id: user.id, userId: user.id);
      } on NotFoundException {
        _log.info(
          'UserAppSettings not found for user ${user.id}. Creating with defaults.',
        );
        final defaultAppSettings = UserAppSettings(
          id: user.id,
          displaySettings: const DisplaySettings(
            baseTheme: AppBaseTheme.system,
            accentTheme: AppAccentTheme.defaultBlue,
            fontFamily: 'SystemDefault',
            textScaleFactor: AppTextScaleFactor.medium,
            fontWeight: AppFontWeight.regular,
          ),
          language: 'en',
          feedPreferences: const FeedDisplayPreferences(
            headlineDensity: HeadlineDensity.standard,
            headlineImageStyle: HeadlineImageStyle.largeThumbnail,
            showSourceInHeadlineFeed: true,
            showPublishDateInHeadlineFeed: true,
          ),
        );
        await _userAppSettingsRepository.create(
          item: defaultAppSettings,
          userId: user.id,
        );
      }

      // Check for UserContentPreferences
      try {
        await _userContentPreferencesRepository.read(id: user.id, userId: user.id);
      } on NotFoundException {
        _log.info(
          'UserContentPreferences not found for user ${user.id}. Creating with defaults.',
        );
        final defaultUserPreferences = UserContentPreferences(
          id: user.id,
          followedCountries: const [],
          followedSources: const [],
          followedTopics: const [],
          savedHeadlines: const [],
        );
        await _userContentPreferencesRepository.create(
          item: defaultUserPreferences,
          userId: user.id,
        );
      }
    } finally {
      // Always release the lock.
      _userCreationLocks.remove(user.id);
    }
  }
}
