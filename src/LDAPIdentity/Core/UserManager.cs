using LDAPIdentity.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace LDAPIdentity.Core
{
    /// <summary>
    /// Provides the APIs for managing user in hybrid LDAP and a persistence store.
    /// </summary>
    /// <typeparam name="TUser">The type encapsulating a user.</typeparam>
    public class UserManager<TUser> : UserManager<TUser, string>
        where TUser : IdentityUser
    {
        public UserManager(IUserStore<TUser> store, IOptions<IdentityOptions> optionsAccessor, IPasswordHasher<TUser> passwordHasher, IEnumerable<IUserValidator<TUser>> userValidators, IEnumerable<IPasswordValidator<TUser>> passwordValidators, ILookupNormalizer keyNormalizer, IdentityErrorDescriber errors, IServiceProvider services, ILogger<UserManager<TUser>> logger, ILDAPService<TUser, string> ldapServices)
            : base(store, optionsAccessor, passwordHasher, new List<IUserValidator<TUser>> { new LocalUserValidator<TUser>(errors) }, passwordValidators, keyNormalizer, errors, services, logger, ldapServices) { }
    }
    /// <summary>
    /// Provides the APIs for managing user in hybrid LDAP and a persistence store.
    /// </summary>
    /// <typeparam name="TUser">The type encapsulating a user.</typeparam>
    /// <typeparam name="TKey">The type used for the primary key for the user.</typeparam>
    public class UserManager<TUser, TKey> : AspNetUserManager<TUser>
        where TUser : IdentityUser<TKey>
        where TKey : IEquatable<TKey>
    {
        /// <summary>
        /// Holds instance of type ILDAPServices. Provide LDAP related services.
        /// </summary>
        private readonly ILDAPService<TUser, TKey> _ldapServices;
        /// <summary>
        /// Constructs a new instance of <see cref="LDAPIdentityHybridUserManager<TUser>"/>
        /// </summary>
        /// <param name="store">The persistence store the manager will operate over.</param>
        /// <param name="optionsAccessor">The accessor used to access the <see cref="Microsoft.AspNetCore.Identity.IdentityOptions"/>.</param>
        /// <param name="passwordHasher"> The password hashing implementation to use when saving passwords.</param>
        /// <param name="userValidators">A collection of <see cref="IUserValidator<TUser>"/> to validate users against.</param>
        /// <param name="passwordValidators">A collection of <see cref="IPasswordValidator<TUser>"/> to validate passwords against.</param>
        /// <param name="keyNormalizer">The <see cref="ILookupNormalizer"/> to use when generating index keys for users.</param>
        /// <param name="errors">The <see cref="IdentityErrorDescriber"/> used to provider error messages.</param>
        /// <param name="services">The <see cref="IServiceProvider"/> used to resolve services.</param>
        /// <param name="logger">The logger used to log messages, warnings and errors.</param>
        /// <param name="ldapServices">The LDAP service which may be accessed for LDAP related operations.</param>
        public UserManager(IUserStore<TUser> store, IOptions<IdentityOptions> optionsAccessor, IPasswordHasher<TUser> passwordHasher, IEnumerable<IUserValidator<TUser>> userValidators, IEnumerable<IPasswordValidator<TUser>> passwordValidators, ILookupNormalizer keyNormalizer, IdentityErrorDescriber errors, IServiceProvider services, ILogger<UserManager<TUser, TKey>> logger, ILDAPService<TUser, TKey> ldapServices)
            : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
        => _ldapServices = ldapServices;
        /// <summary>
        /// Changes a user's password after confirming the specified <paramref name="currentPassword"/> is correct,
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user whose password should be set.</param>
        /// <param name="currentPassword">The current password to validate before changing.</param>
        /// <param name="newPassword">The new password to set for the specified <paramref name="user"/>.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public override async Task<IdentityResult> ChangePasswordAsync(TUser user, string currentPassword, string newPassword)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (await VerifyPasswordAsync(null, user, currentPassword) != PasswordVerificationResult.Failed)
            {
                return await UpdatePasswordHash(user, newPassword);
            }
            Logger.LogWarning(2, "Change password failed for user {userId}.", await GetUserIdAsync(user));
            return IdentityResult.Failed(ErrorDescriber.PasswordMismatch());
        }
        /// <summary>
        /// Updates a users emails in LDAP and in default store, if the specified email change <paramref name="token"/> is valid for the user.
        /// </summary>
        /// <param name="user">The user whose email should be updated.</param>
        /// <param name="newEmail">The new email address.</param>
        /// <param name="token">The change email token to be verified.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public override async Task<IdentityResult> ChangeEmailAsync(TUser user, string newEmail, string token)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            // Make sure the token is valid and the stamp matches
            if (!await VerifyUserTokenAsync(user, Options.Tokens.ChangeEmailTokenProvider, GetChangeEmailTokenPurpose(newEmail), token))
            {
                return IdentityResult.Failed(ErrorDescriber.InvalidToken());
            }
            await _ldapServices.ChangeEmailAsync(user, newEmail, CancellationToken);
            return await base.ChangeEmailAsync(user, newEmail, token);
        }
        /// <summary>
        /// Returns a <see cref="PasswordVerificationResult"/> indicating the result of password verification with LDAP.
        /// </summary>
        /// <param name="store">The store containing a user's password.</param>
        /// <param name="user">The user whose password should be verified.</param>
        /// <param name="password">The password to verify.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="PasswordVerificationResult"/> of the operation.
        /// </returns>
        protected override async Task<PasswordVerificationResult> VerifyPasswordAsync(IUserPasswordStore<TUser> store, TUser user, string password)
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentNullException(nameof(password));
            }
            /// Validate user's password in LDAP
            if (await _ldapServices.VerifyPasswordAsync(user, password, CancellationToken))
            {

                var _user = await base.FindByNameAsync(user.UserName);
                if (_user == null)
                {
                    /// Create the user on deafult store
                    var _result = await base.CreateAsync(user);
                    if (!_result.Succeeded)
                    {
                        throw new AggregateException(_result.Errors.Select(e => new Exception(e.Description) { Source = e.Code }));
                    }
                    /// Fetch user's claims stored in LDAP
                    var _claims = await _ldapServices.GetClaimsAsync(user, CancellationToken);
                    if (_claims.Count() > 0)
                        /// Create user's claims on deafult store
                        _result = await base.AddClaimsAsync(user, _claims);
                    if (!_result.Succeeded)
                    {
                        throw new AggregateException(_result.Errors.Select(e => new Exception(e.Description) { Source = e.Code }));
                    }
                }
                return PasswordVerificationResult.Success;
            }
            return PasswordVerificationResult.Failed;
        }
        /// <summary>
        /// Creates the specified user in LDAP and the backing store with random password, as an asynchronous operation.
        /// </summary>
        /// <param name="user"> The user to create.</param>
        /// <returns>The System.Threading.Tasks.Task that represents the asynchronous operation, the Microsoft.AspNetCore.Identity.IdentityResult of the operation</returns>
        public override async Task<IdentityResult> CreateAsync(TUser user)
        {
            /// Redirects control to local <see cref="CreateAsync(TUser,string)"/> method, to make sure user is also created on LDAP.
            return await CreateAsync(user, Guid.NewGuid().ToString());
        }
        /// <summary>
        /// Creates the specified user with given password in LDAP and the backing store (No Password in backing store), as an asynchronous operation.
        /// </summary>
        /// <param name="user"> The user to create.</param>
        /// <param name="password">The password for the user to hash and store.</param>
        /// <returns>The System.Threading.Tasks.Task that represents the asynchronous operation, the Microsoft.AspNetCore.Identity.IdentityResult of the operation</returns>
        public override async Task<IdentityResult> CreateAsync(TUser user, string password)
        {
            /// Create user in LDAP
            await _ldapServices.CreateAsync(user, password, CancellationToken);
            /// Create user locally
            return await base.CreateAsync(user);
        }
        /// <summary>
        /// Updates a user's password hash in LDAP.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="newPassword">The new password.</param>
        /// <param name="validatePassword">Whether to validate the password.</param>
        /// <returns>The System.Threading.Tasks.Task that represents the asynchronous operation, the Microsoft.AspNetCore.Identity.IdentityResult of the operation</returns>
        protected override async Task<IdentityResult> UpdatePasswordHash(TUser user, string newPassword, bool validatePassword = true)
        {
            /// Default validation check as in base method <see cref="base.UpdatePasswordHash"/>.
            if (validatePassword)
                foreach (var item in PasswordValidators)
                {
                    var _validation = await item.ValidateAsync(this, user, newPassword);
                    if (!_validation.Succeeded)
                    {
                        return _validation;
                    }
                }
            /// Update user's password in LDAP
            await _ldapServices.UpdatePasswordAsync(user, newPassword, CancellationToken);
            return IdentityResult.Success;
        }
        /// <summary>
        /// Adds the specified <paramref name="claims"/> to the <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to add the claim to.</param>
        /// <param name="claims">The claims to add.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public override async Task<IdentityResult> AddClaimsAsync(TUser user, IEnumerable<Claim> claims)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (claims == null)
                throw new ArgumentNullException(nameof(claims));
            if (claims.Count() == 0)
            {
                return IdentityResult.Success;
            }
            /// Add user's claims in LDAP
            await _ldapServices.AddClaimsAsync(user, claims, CancellationToken);
            /// Add user's claims in default store
            return await base.AddClaimsAsync(user, claims);
        }
        /// <summary>
        /// Removes the specified <paramref name="claim"/> from the given <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to remove the specified <paramref name="claim"/> from.</param>
        /// <param name="claim">The <see cref="Claim"/> to remove.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the operation.
        /// </returns>
        public override async Task<IdentityResult> RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (claims == null)
                throw new ArgumentNullException(nameof(claims));
            if (claims.Count() == 0)
            {
                return IdentityResult.Success;
            }
            /// Remove user's claims from LDAP
            await _ldapServices.RemoveClaimsAsync(user, claims, CancellationToken);
            /// Remove user's claims from default store
            return await base.RemoveClaimsAsync(user, claims);
        }
        /// <summary>
        /// Replaces the given <paramref name="claim"/> on the specified <paramref name="user"/> with the <paramref name="newClaim"/>
        /// </summary>
        /// <param name="user">The user to replace the claim on.</param>
        /// <param name="claim">The claim to replace.</param>
        /// <param name="newClaim">The new claim to replace the existing <paramref name="claim"/> with.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the operation.
        /// </returns>
        public override async Task<IdentityResult> ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (claim == null)
                throw new ArgumentNullException(nameof(claim));
            if (newClaim == null)
                throw new ArgumentNullException(nameof(newClaim));
            if (claim.Equals(newClaim))
            {
                return IdentityResult.Success;
            }
            /// Replace user's claims in LDAP
            await _ldapServices.ReplaceClaimAsync(user, claim, newClaim, CancellationToken);
            /// Replace user's claim in default store
            return await base.ReplaceClaimAsync(user, claim, newClaim);
        }
        public override async Task<IdentityResult> SetPhoneNumberAsync(TUser user, string phoneNumber)
        {
            await _ldapServices.SetPhoneNumberAsync(user, phoneNumber, CancellationToken);
            return await base.SetPhoneNumberAsync(user, phoneNumber);
        }
        /// <summary>
        /// Finds user in local store if not found search is continued on LDAP and returns a user, if any, who has the specified user name.
        /// </summary>
        /// <param name="userName">The user name to search for.</param>
        /// <returns>The System.Threading.Tasks.Task that represents the asynchronous operation, containing the user matching the specified userName if it exists.</returns>
        public override async Task<TUser> FindByNameAsync(string userName)
        {
            /// Try to find user in default store.
            var _user = await base.FindByNameAsync(userName);
            if (_user == null)
            {
                // Try to find user in LDAP.
                _user = await _ldapServices.FindByAttributeAsync(IdentityType.SamAccountName, userName, CancellationToken);
            }
            return _user;
        }
        /// <summary>
        /// Finds and returns a user, if any in local store, who has the specified user name.
        /// </summary>
        /// <param name="userName">The user name to search for.</param>
        /// <returns>The System.Threading.Tasks.Task that represents the asynchronous operation, containing the user matching the specified userName if it exists.</returns>
        public Task<TUser> FindLocallyByNameAsync(string userName)
        {
            return base.FindByNameAsync(userName);
        }
    }
}