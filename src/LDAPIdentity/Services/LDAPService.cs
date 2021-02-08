using LDAPIdentity.Extensions.UserPrincipalExtension;
using LDAPIdentity.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace LDAPIdentity.Servicess
{
    sealed class LDAPService<TUser, TKey> : ILDAPService<TUser, TKey>
        where TUser : IdentityUser<TKey>
        where TKey : IEquatable<TKey>
    {
        private readonly LDAPIdentityOptions _options;
        public LDAPService(IOptions<LDAPIdentityOptions> options)
            => _options = options.Value;
        public Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
        {
            return Task.Run(() =>
            {
                using var _principalContext = GetNewPrincipalContext();
                using var _userPrincipal = UserPrincipal.FindByIdentity(_principalContext, IdentityType.SamAccountName, user.UserName);
                _userPrincipal.AddClaims(claims);
                _userPrincipal.Save();
            }, cancellationToken);
        }
        public Task ChangeEmailAsync(TUser user, string newEmail, CancellationToken cancellationToken = default)
        {
            return Task.Run(() =>
            {
                using var _principalContext = GetNewPrincipalContext();
                using var _userPrincipal = UserPrincipal.FindByIdentity(_principalContext, IdentityType.SamAccountName, user.UserName);
                _userPrincipal
                    .ChangeEmail(newEmail, _options.UserDomain);
            }, cancellationToken);
        }
        public Task CreateAsync(TUser user, string password, CancellationToken cancellationToken = default)
        {
            return Task.Run(() =>
            {
                using var _userPrincipal = GetNewPrincipalContext().CreateUserPrincipal<TUser, TKey>(user, _options.UserDomain);
                _userPrincipal
                    .SetPassword(password);
                _userPrincipal.Save();
            }, cancellationToken);
        }
        public Task DeleteAsync(TUser user, CancellationToken cancellationToken = default)
        {
            return Task.Run(() =>
            {
                using var _principalContext = GetNewPrincipalContext();
                using var _userPrincipal = UserPrincipal.FindByIdentity(_principalContext, IdentityType.SamAccountName, user.UserName);
                _userPrincipal.Delete();
            }, cancellationToken);
        }
        public Task<TUser> FindByAttributeAsync(IdentityType identityType, string value, CancellationToken cancellationToken = default)
        {
            return Task.Run(() =>
            {
                using var _principalContext = GetNewPrincipalContext();
                using var _userPrincipal = UserPrincipal.FindByIdentity(_principalContext, identityType, value);
                return _userPrincipal.CreateUser<TUser, TKey>();
            }, cancellationToken);
        }
        public Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken = default)
        {
            return Task.Run<IList<Claim>>(() =>
            {
                using var _principalContext = GetNewPrincipalContext();
                using var _userPrincipal = UserPrincipal.FindByIdentity(_principalContext, IdentityType.SamAccountName, user.UserName);
                return _userPrincipal.GetClaims().ToList();
            }, cancellationToken);
        }
        public Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
        {
            return Task.Run(() =>
            {
                using var _principalContext = GetNewPrincipalContext();
                using var _userPrincipal = UserPrincipal.FindByIdentity(_principalContext, IdentityType.SamAccountName, user.UserName);
                _userPrincipal.RemoveClaims(claims);
                _userPrincipal.Save();
            }, cancellationToken);
        }
        public Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken = default)
        {
            return Task.Run(() =>
            {
                using var _principalContext = GetNewPrincipalContext();
                using var _userPrincipal = UserPrincipal.FindByIdentity(_principalContext, IdentityType.SamAccountName, user.UserName);
                _userPrincipal.RemoveClaims(new[] { claim });
                _userPrincipal.AddClaims(new[] { newClaim });
                _userPrincipal.Save();
            }, cancellationToken);
        }
        public Task SetPhoneNumberAsync(TUser user, string phoneNumber, CancellationToken cancellationToken = default)
        {
            return Task.Run(() =>
            {
                using var _principalContext = GetNewPrincipalContext();
                using var _userPrincipal = UserPrincipal.FindByIdentity(_principalContext, IdentityType.SamAccountName, user.UserName);
                _userPrincipal.VoiceTelephoneNumber = phoneNumber;
                _userPrincipal.Save();
            }, cancellationToken);
        }
        public Task UpdatePasswordAsync(TUser user, string newPassword, CancellationToken cancellationToken = default)
        {
            return Task.Run(() =>
            {
                using var _principalContext = GetNewPrincipalContext();
                using var _userPrincipal = UserPrincipal.FindByIdentity(_principalContext, IdentityType.SamAccountName, user.UserName);
                _userPrincipal.SetPassword(newPassword);
                _userPrincipal.Save();
            }, cancellationToken);
        }
        public Task<bool> VerifyPasswordAsync(TUser user, string password, CancellationToken cancellationToken = default)
        {
            return Task.Run(() =>
            {
                using var _principalContext = GetNewPrincipalContext();
                return _principalContext.ValidateCredentials(user.UserName, password);
            }, cancellationToken);
        }
        /// <summary>
        /// Returns a new instance of <see cref="PrincipalContext"/>, with the LDAPOptions supplied information.
        /// </summary>
        /// <returns>Instantiated object of <see cref="PrincipalContext"/></returns>
        private PrincipalContext GetNewPrincipalContext()
        {
            return new PrincipalContext(ContextType.Domain, _options.Hostname, _options.OUBase, _options.BindDn, _options.BindCredentials);
        }
    }
}